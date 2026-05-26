#!/usr/bin/env python3
"""
Fast corpus-fetch using GitHub archive downloads.

Instead of cloning full repos, downloads just the source tree at the
specific commit as a tarball. This is 10-100x faster for large repos.

For `sha~1` refs, resolves the parent SHA via the GitHub API first.

Usage:
    python scripts/fast_fetch.py [--java-only] [--django-only]
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

CORPUS_ROOT = Path("benchmarks/realworld")
TOKEN = os.environ.get("GITHUB_TOKEN", "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")


def github_api(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    })
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())


def resolve_ref(repo: str, git_ref: str) -> str:
    """Resolve a git ref expression (like sha~1) to an actual SHA."""
    if "~" not in git_ref and "^" not in git_ref:
        # Might be a tag object SHA — dereference to commit
        return dereference_to_commit(repo, git_ref)

    base_sha = git_ref.split("~")[0].split("^")[0]
    # Get the number of parents to go back
    if "~" in git_ref:
        n = int(git_ref.split("~")[1]) if "~" in git_ref and git_ref.split("~")[1] else 1
    else:
        n = 1

    # Dereference base if it's a tag object
    base_sha = dereference_to_commit(repo, base_sha)

    # Walk back n parents via GitHub API
    sha = base_sha
    for _ in range(n):
        data = github_api(f"https://api.github.com/repos/{repo}/commits/{sha}")
        parents = data.get("parents", [])
        if not parents:
            raise ValueError(f"No parent for {sha}")
        sha = parents[0]["sha"]

    return sha


def dereference_to_commit(repo: str, sha: str) -> str:
    """If sha points to a tag object, dereference to the underlying commit."""
    try:
        data = github_api(f"https://api.github.com/repos/{repo}/git/tags/{sha}")
        # It's an annotated tag — follow to commit
        obj = data.get("object", {})
        if obj.get("type") == "commit":
            return obj["sha"]
        elif obj.get("type") == "tag":
            # Nested tag (rare)
            return dereference_to_commit(repo, obj["sha"])
    except Exception:
        pass
    # Not a tag object, assume it's a commit SHA already
    return sha


def download_tree(repo: str, sha: str, target_dir: Path, source_subdir: str = None, timeout: int = 120) -> None:
    """Download and extract the source tree at a specific commit.
    
    Tries tarball first with timeout. Falls back to sparse checkout for large repos.
    """
    url = f"https://github.com/{repo}/archive/{sha}.tar.gz"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {TOKEN}",
    })

    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = tmp.name
            resp = urllib.request.urlopen(req, timeout=timeout)
            # Read with size check - skip if > 200MB
            data = b""
            chunk_size = 1024 * 1024  # 1MB
            max_size = 200 * 1024 * 1024  # 200MB
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                data += chunk
                if len(data) > max_size:
                    os.unlink(tmp_path)
                    raise TimeoutError(f"Tarball > 200MB, switching to sparse checkout")
            tmp.write(data)

        target_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tmp_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                raise ValueError("Empty tarball")

            prefix = members[0].name.split("/")[0] + "/"

            for member in members:
                if not member.name.startswith(prefix):
                    continue
                member.name = member.name[len(prefix):]
                if not member.name:
                    continue
                # Security: prevent path traversal
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    continue
                # If source_subdir specified, only extract files in that subtree
                # (still downloads all but saves disk space/extraction time)
                tar.extract(member, target_dir, filter="data")
        os.unlink(tmp_path)
    except (TimeoutError, urllib.error.URLError, Exception) as e:
        # Fallback: sparse checkout with only the needed directory
        if target_dir.exists():
            shutil.rmtree(target_dir)
        sparse_checkout(repo, sha, target_dir, source_subdir)


def sparse_checkout(repo: str, sha: str, target_dir: Path, source_subdir: str = None) -> None:
    """Use git sparse-checkout to get only the needed subdirectory."""
    target_dir.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"
    
    subprocess.run(
        ["git", "init"], cwd=target_dir, 
        capture_output=True, check=True
    )
    subprocess.run(
        ["git", "remote", "add", "origin", url], cwd=target_dir,
        capture_output=True, check=True
    )
    subprocess.run(
        ["git", "sparse-checkout", "init", "--cone"], cwd=target_dir,
        capture_output=True, check=True
    )
    
    # Set sparse-checkout patterns
    patterns = [source_subdir] if source_subdir else ["."]
    subprocess.run(
        ["git", "sparse-checkout", "set"] + patterns, cwd=target_dir,
        capture_output=True, check=True
    )
    
    # Fetch only the specific commit with depth=1
    subprocess.run(
        ["git", "fetch", "--depth=1", "origin", sha], cwd=target_dir,
        capture_output=True, check=True, timeout=180
    )
    subprocess.run(
        ["git", "checkout", "FETCH_HEAD"], cwd=target_dir,
        capture_output=True, check=True
    )


def main():
    java_only = "--java-only" in sys.argv
    django_only = "--django-only" in sys.argv

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

    # Cache resolved SHAs to avoid redundant API calls
    sha_cache: dict[str, str] = {}
    success = 0
    skipped = 0
    failed = 0

    for mpath, data in manifests:
        app_name = mpath.parent.name
        repo_url = data.get("repo_url", "")
        git_ref = data.get("git_ref", "")
        checkout_dir = data.get("checkout_dir", "src")
        target_path = mpath.parent / checkout_dir

        if target_path.exists():
            # Count java files to check if it's a real checkout
            java_count = len(list(target_path.rglob("*.java"))) if data.get("framework") == "spring" else -1
            py_count = len(list(target_path.rglob("*.py"))) if data.get("framework") == "django" else -1
            if java_count > 0 or py_count > 0:
                skipped += 1
                continue
            elif java_count == 0 or py_count == 0:
                # Empty checkout, re-fetch
                shutil.rmtree(target_path)
            else:
                skipped += 1
                continue

        if not repo_url or not git_ref:
            print(f"  SKIP {app_name}: missing repo_url or git_ref")
            skipped += 1
            continue

        # Extract owner/repo from URL
        parts = repo_url.rstrip("/").split("/")
        repo = f"{parts[-2]}/{parts[-1]}"

        # Resolve the actual SHA
        cache_key = f"{repo}:{git_ref}"
        if cache_key in sha_cache:
            sha = sha_cache[cache_key]
        else:
            try:
                sha = resolve_ref(repo, git_ref)
                sha_cache[cache_key] = sha
            except Exception as e:
                print(f"  ✗ {app_name}: resolve failed: {e}")
                failed += 1
                continue

        # Download
        try:
            source_subdir = data.get("source_subdir", "")
            print(f"  ↓ {app_name} [{repo}@{sha[:10]}] ...", end="", flush=True)
            download_tree(repo, sha, target_path, source_subdir=source_subdir)
            # Quick sanity check
            if data.get("framework") == "spring":
                n_java = len(list(target_path.rglob("*.java")))
                print(f" OK ({n_java} .java files)")
            elif data.get("framework") == "django":
                n_py = len(list(target_path.rglob("*.py")))
                print(f" OK ({n_py} .py files)")
            else:
                print(f" OK")
            success += 1
        except Exception as e:
            print(f" FAILED: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"DONE: {success} downloaded, {skipped} existing, {failed} failed")


if __name__ == "__main__":
    main()
