#!/usr/bin/env python3
"""
Quick diagnostic: run the Spring extractor on each fetched Java benchmark
and report what endpoints it finds. Helps identify extractor issues.

Usage:
    python scripts/test_java_extraction.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pfg.eval.manifest import discover_manifests
from pfg.extractors.spring.build import build_pfg


def main():
    corpus = Path("benchmarks/realworld")
    manifests = discover_manifests(corpus)

    java_manifests = [m for m in manifests if m.framework == "spring"]
    print(f"Java/Spring manifests: {len(java_manifests)}")
    print("=" * 70)

    success = 0
    fail = 0
    no_checkout = 0

    for m in java_manifests:
        src_root = m.project_root
        if not src_root.exists():
            no_checkout += 1
            continue

        print(f"\n{'─' * 70}")
        print(f"  {m.application}")
        print(f"  source_root: {src_root}")

        try:
            pfg = build_pfg(src_root, application=m.application)
            endpoints = pfg.endpoints()
            data_accesses = pfg.data_accesses()

            print(f"  ✓ nodes={len(pfg.nodes)} edges={len(pfg.edges)} "
                  f"endpoints={len(endpoints)} data_access={len(data_accesses)}")

            if endpoints:
                # Show first few endpoints
                for ep in endpoints[:5]:
                    a = ep.attrs.model_dump()
                    auth = "AUTH" if a.get("requires_auth") else "NOAUTH"
                    role = a.get("required_role", "NONE")
                    print(f"    {a['http_method']:6s} {a['route'][:50]:50s} [{auth}] role={role}")
                if len(endpoints) > 5:
                    print(f"    ... and {len(endpoints) - 5} more")
            else:
                print(f"  ⚠ NO ENDPOINTS FOUND — extractor needs refinement")

            success += 1
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            fail += 1

    print(f"\n{'=' * 70}")
    print(f"SUMMARY: {success} OK, {fail} FAILED, {no_checkout} not fetched yet")
    print(f"Total Java manifests: {len(java_manifests)}")


if __name__ == "__main__":
    main()
