#!/usr/bin/env python3
"""
Fetch benchmark corpus sources using git sparse-checkout.

Only downloads the specific subdirectory needed (source_subdir from manifest),
avoiding full monorepo downloads. Uses a shared bare cache per repo to avoid
redundant network operations.

Usage:
    python scripts/sparse_fetch.py [--java-only] [--django-only] [--force]
"""
import json
import os
import subprocess
import sys
import urllib.request
import yaml
from pathlib import Path

CORPUS_ROOT = Path("benchmarks/realworld")
CACHE_ROOT = Path(".corpus_cache")
TOKEN = os.environ.get("GITHUB_TOKEN", "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")


def github_api(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    })
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def dereference_to_commit(repo: str, sha: str) -> str:
    """If sha is an annotated tag object, dereference to the underlying commit."""
    try:
        data = github_api(f"https://api.github.com/repos/{repo}/git/tags/{sha}")
        obj = data.get("object", {})
        if obj.get("type") == "commit":
            return obj["sha"]
        elif obj.get("type") == "tag":
            return dereference_to_commit(repo, obj["sha"])
    except Exception:
        pass
    return sha


def resolve_ref(repo: str, git_ref: str) -> str:
    """Resolve a git ref expression (like sha~1) to an actual commit SHA."""
    if "~" not in git_ref and "^" not in git_ref:
        return dereference_to_commit(repo, git_ref)

    base_sha = git_ref.split("~")[0].split("^")[0]
    n = 1
    if "~" in git_ref:
        parts = git_ref.split("~")
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1

    base_sha = dereference_to_commit(repo, base_sha)

    sha = base_sha
    for _ in range(n):
        data = github_api(f"https://api.github.com/repos/{repo}/commits/{sha}")
        parents = data.get("parents", [])
        if not parents:
            raise ValueError(f"No parent for {sha}")
        sha = parents[0]["sha"]
    return sha


def sparse_checkout(repo_url: str, sha: str, target_dir: Path, source_subdir: str = "") -> int:
    """
    Sparse-checkout at depth=1 for a specific commit.
    Only downloads blobs in the specified subdirectory.
    Returns count of .java files fetched.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    def run(cmd, **kwargs):
        return subprocess.run(
            cmd, cwd=target_dir, capture_output=True, text=True,
            timeout=300, **kwargs
        )

    # Init repo
    run(["git", "init"], check=True)
    run(["git", "remote", "add", "origin", repo_url], check=True)

    # Configure sparse checkout
    run(["git", "sparse-checkout", "init", "--cone"], check=True)
    if source_subdir:
        run(["git", "sparse-checkout", "set", source_subdir], check=True)
    
    # Fetch only the commit we need at depth 1 (minimal history)
    result = run(["git", "fetch", "--depth=1", "--filter=blob:none", "origin", sha])
    if result.returncode != 0:
        # Some old commits can't be fetched at depth=1, try without depth limit
        result = run(["git", "fetch", "--filter=blob:none", "origin", sha])
        if result.returncode != 0:
            raise RuntimeError(f"git fetch failed: {result.stderr}")
    
    # Checkout
    result = run(["git", "checkout", sha])
    if result.returncode != 0:
        result = run(["git", "checkout", "FETCH_HEAD"])
        if result.returncode != 0:
            raise RuntimeError(f"git checkout failed: {result.stderr}")
    
    return len(list(target_dir.rglob("*.java")))


def main():
    java_only = "--java-only" in sys.argv
    django_only = "--django-only" in sys.argv
    force = "--force" in sys.argv

    # Discover manifests
    manifests = []
    for mpath in sorted(CORPUS_ROOT.glob("*/manifest.yaml")):
        if mpath.parent.name == "_template":
            continue
        try:
            data = yaml.safe_load(mpath.read_text())
            if java_only and data.get("framework") != "spring":
                continue
            if django_only and data.get("framework") != "django":
                continue
            manifests.append((mpath, data))
        except Exception as e:
            print(f"ERROR loading {mpath}: {e}")

    print(f"Manifests to fetch: {len(manifests)}")
    print("=" * 60)

    sha_cache: dict[str, str] = {}
    success = 0
    skipped = 0
    failed = 0
    failed_list = []

    for mpath, data in manifests:
        app_name = mpath.parent.name
        repo_url = data.get("repo_url", "")
        git_ref = data.get("git_ref", "")
        checkout_dir = data.get("checkout_dir", "src")
        source_subdir = data.get("source_subdir", "")
        target_path = mpath.parent / checkout_dir

        # Skip existing checkouts
        if not force and target_path.exists():
            n_java = len(list(target_path.rglob("*.java")))
            n_py = len(list(target_path.rglob("*.py")))
            if n_java > 0 or n_py > 0:
                print(f"  ✓ {app_name} (existing, {n_java} java / {n_py} py)")
                skipped += 1
                continue

        if not repo_url or not git_ref:
            print(f"  SKIP {app_name}: missing repo_url or git_ref")
            skipped += 1
            continue

        # Extract owner/repo from URL
        parts = repo_url.rstrip("/").split("/")
        repo = f"{parts[-2]}/{parts[-1]}"

        # Resolve the actual commit SHA
        cache_key = f"{repo}:{git_ref}"
        if cache_key in sha_cache:
            sha = sha_cache[cache_key]
        else:
            try:
                sha = resolve_ref(repo, git_ref)
                sha_cache[cache_key] = sha
                print(f"  → {app_name}: resolved {git_ref[:20]}... → {sha[:10]}")
            except Exception as e:
                print(f"  ✗ {app_name}: resolve failed: {e}")
                failed += 1
                failed_list.append(app_name)
                continue

        # Download via sparse checkout
        try:
            subdir_label = source_subdir or "(full tree)"
            print(f"  ↓ {app_name} [{subdir_label}] ...", end="", flush=True)
            
            # Clean target if it exists but is empty/broken
            if target_path.exists():
                import shutil
                shutil.rmtree(target_path)
            
            n_java = sparse_checkout(repo_url, sha, target_path, source_subdir)
            print(f" OK ({n_java} .java files)")
            success += 1
        except Exception as e:
            print(f" FAILED: {e}")
            failed += 1
            failed_list.append(app_name)
            # Clean up broken checkout
            if target_path.exists():
                import shutil
                shutil.rmtree(target_path)

    print(f"\n{'=' * 60}")
    print(f"DONE: {success} downloaded, {skipped} existing, {failed} failed")
    if failed_list:
        print(f"Failed: {', '.join(failed_list)}")


if __name__ == "__main__":
    main()
