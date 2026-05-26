#!/usr/bin/env python3
"""
Smart corpus-fetch: clones each unique repo ONCE into a shared cache,
then creates git worktrees for each manifest's specific commit.

This avoids cloning keycloak/keycloak 15 times.

Usage:
    python scripts/smart_fetch.py [--force]
"""
import subprocess
import sys
import yaml
from pathlib import Path


CORPUS_ROOT = Path("benchmarks/realworld")
CACHE_DIR = Path(".corpus_cache")


def run_git(args: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, ["git", *args], result.stdout, result.stderr
        )
    return result.stdout.strip()


def get_repo_cache_path(repo_url: str) -> Path:
    """Convert repo URL to a cache directory name."""
    # https://github.com/keycloak/keycloak -> keycloak__keycloak
    parts = repo_url.rstrip("/").split("/")
    owner_repo = f"{parts[-2]}__{parts[-1]}"
    return CACHE_DIR / owner_repo


def ensure_bare_clone(repo_url: str) -> Path:
    """Clone or update a bare repo in the cache."""
    cache_path = get_repo_cache_path(repo_url)
    if cache_path.exists():
        # Already cached, just fetch updates
        print(f"    cache hit: {cache_path.name}")
        try:
            run_git(["fetch", "--all"], cwd=cache_path)
        except subprocess.CalledProcessError:
            pass  # Offline or rate-limited, use what we have
        return cache_path

    # Clone as bare with blob filter
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"    cloning -> {cache_path.name} ...")
    run_git([
        "clone", "--bare", "--filter=blob:none",
        repo_url, str(cache_path)
    ])
    return cache_path


def create_worktree(cache_path: Path, target_path: Path, git_ref: str) -> None:
    """Create a worktree from the cached bare clone at a specific ref."""
    if target_path.exists():
        # Already exists — verify it's correct
        return

    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Resolve the base SHA (handle ~1 expressions)
    base_ref = git_ref.split("~")[0].split("^")[0]

    # Fetch the specific ref if needed (for SHAs not on main branch)
    try:
        run_git(["rev-parse", "--verify", base_ref], cwd=cache_path)
    except subprocess.CalledProcessError:
        try:
            run_git(["fetch", "origin", base_ref], cwd=cache_path)
        except subprocess.CalledProcessError:
            pass

    # Create worktree
    try:
        run_git(["worktree", "add", "--detach", str(target_path.resolve()), git_ref], cwd=cache_path)
    except subprocess.CalledProcessError as e:
        # Worktree might fail if ref isn't found, try with base + reset
        if "~" in git_ref or "^" in git_ref:
            # Try: create at base, then move HEAD back
            run_git(["worktree", "add", "--detach", str(target_path.resolve()), base_ref], cwd=cache_path)
            run_git(["checkout", "--detach", git_ref], cwd=target_path)
        else:
            raise


def main():
    force = "--force" in sys.argv

    # Discover all manifests
    manifests = []
    for mpath in sorted(CORPUS_ROOT.glob("*/manifest.yaml")):
        if mpath.parent.name == "_template":
            continue
        try:
            data = yaml.safe_load(mpath.read_text())
            manifests.append((mpath, data))
        except Exception as e:
            print(f"ERROR loading {mpath}: {e}")

    print(f"Found {len(manifests)} manifests")

    # Group by repo_url
    by_repo: dict[str, list[tuple[Path, dict]]] = {}
    for mpath, data in manifests:
        repo_url = data.get("repo_url", "")
        if repo_url:
            by_repo.setdefault(repo_url, []).append((mpath, data))
        else:
            print(f"  SKIP {mpath.parent.name}: no repo_url")

    print(f"Unique repos: {len(by_repo)}")
    print()

    # Process each unique repo
    success = 0
    skipped = 0
    failed = 0

    for repo_url, repo_manifests in sorted(by_repo.items()):
        repo_name = repo_url.rstrip("/").split("/")[-1]
        print(f"[{repo_name}] {len(repo_manifests)} manifests from {repo_url}")

        # Clone/update cache
        try:
            cache_path = ensure_bare_clone(repo_url)
        except Exception as e:
            print(f"  FAILED to cache: {e}")
            failed += len(repo_manifests)
            continue

        # Create worktree for each manifest
        for mpath, data in repo_manifests:
            app_name = mpath.parent.name
            git_ref = data.get("git_ref", "")
            checkout_dir = data.get("checkout_dir", "src")
            target_path = mpath.parent / checkout_dir

            if target_path.exists() and not force:
                print(f"    ✓ {app_name} (exists)")
                skipped += 1
                continue

            if not git_ref:
                print(f"    SKIP {app_name}: no git_ref")
                skipped += 1
                continue

            try:
                create_worktree(cache_path, target_path, git_ref)
                print(f"    ✓ {app_name}")
                success += 1
            except Exception as e:
                print(f"    ✗ {app_name}: {e}")
                failed += 1

    print(f"\n{'=' * 60}")
    print(f"DONE: {success} created, {skipped} existing/skipped, {failed} failed")
    print(f"Total checkouts: {success + skipped}")


if __name__ == "__main__":
    main()
