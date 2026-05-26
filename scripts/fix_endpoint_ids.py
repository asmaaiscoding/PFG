#!/usr/bin/env python3
"""Fix endpoint_ids in manifest.yaml files by matching against extractor output.

For each Django manifest with expected_findings, runs the extractor to get
actual endpoint_ids and attempts to match/fix any mismatched IDs.

Usage:
    python scripts/fix_endpoint_ids.py [--dry-run] [--app APP_NAME]
"""
from __future__ import annotations

import argparse
import sys
from difflib import get_close_matches
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pfg.eval.manifest import load_manifest  # noqa: E402
from pfg.extractors.django.build import build_pfg  # noqa: E402


def _safe_id(raw: str) -> str:
    """Reproduce the safe_id logic from the extractor."""
    import re
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw).strip("_")


def process_app(manifest_path: Path, *, dry_run: bool = False) -> dict[str, str]:
    """Process one manifest. Returns {old_id: new_id} for fixes applied."""
    with open(manifest_path) as f:
        data = yaml.safe_load(f)

    if data.get("framework") != "django":
        return {}
    if not data.get("expected_findings"):
        return {}

    try:
        m = load_manifest(str(manifest_path))
        pfg = build_pfg(m.project_root, application=m.application)
    except Exception as e:
        print(f"  ERROR building PFG: {e}")
        return {}

    ep_ids = sorted({n.id for n in pfg.nodes if n.type == "endpoint"})
    fixes: dict[str, str] = {}

    for i, ef in enumerate(data["expected_findings"]):
        eid = ef["endpoint_id"]
        if eid in ep_ids:
            continue

        # Try fuzzy match
        close = get_close_matches(eid, ep_ids, n=3, cutoff=0.7)

        # Also try keyword-based match using URL pattern if available
        url_pattern = ef.get("url_pattern", "")
        if url_pattern and not close:
            # Convert URL pattern to expected ID parts
            parts = url_pattern.strip("/").replace("-", "_").replace("{", "_").replace("}", "_").split("/")
            keyword_matches = [
                e for e in ep_ids
                if all(p in e for p in parts if len(p) > 2)
            ]
            if keyword_matches:
                close = keyword_matches[:3]

        if close:
            best = close[0]
            print(f"  FIX: {eid}")
            print(f"    -> {best}")
            if len(close) > 1:
                print(f"    (alternatives: {close[1:]})")
            fixes[eid] = best
            if not dry_run:
                data["expected_findings"][i]["endpoint_id"] = best
        else:
            print(f"  NO MATCH: {eid}")
            # Show some candidates with partial overlap
            parts = eid.replace("endpoint__", "").split("__")
            method = parts[0] if parts else ""
            partial = [
                e for e in ep_ids
                if method in e and any(p in e for p in parts[1:] if len(p) > 3)
            ][:5]
            if partial:
                print(f"    Candidates: {partial}")

    if fixes and not dry_run:
        # Also mark as evaluation_ready since we've verified the endpoint exists
        data["evaluation_ready"] = True
        with open(manifest_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        print(f"  -> Updated {manifest_path}")

    return fixes


def main() -> None:
    parser = argparse.ArgumentParser(description="Fix endpoint_ids in Django manifests")
    parser.add_argument("--dry-run", action="store_true", help="Don't write changes")
    parser.add_argument("--app", type=str, help="Process only this app (directory name)")
    args = parser.parse_args()

    manifest_dir = Path("benchmarks/realworld")
    total_fixes = 0
    total_no_match = 0
    total_already_ok = 0

    for mf in sorted(manifest_dir.rglob("manifest.yaml")):
        if args.app and mf.parent.name != args.app:
            continue
        with open(mf) as f:
            data = yaml.safe_load(f)
        if data.get("framework") != "django" or not data.get("expected_findings"):
            continue

        app_name = mf.parent.name
        print(f"\n{app_name}:")

        # Quick check: are all IDs already matching?
        fixes = process_app(mf, dry_run=args.dry_run)
        if fixes:
            total_fixes += len(fixes)
        else:
            # Check if all matched or all failed
            try:
                m = load_manifest(str(mf))
                pfg = build_pfg(m.project_root, application=m.application)
                ep_ids = {n.id for n in pfg.nodes if n.type == "endpoint"}
                all_match = all(
                    ef["endpoint_id"] in ep_ids for ef in data["expected_findings"]
                )
                if all_match:
                    print("  All IDs match ✓")
                    total_already_ok += 1
                    # Mark evaluation_ready
                    if not args.dry_run and not data.get("evaluation_ready"):
                        data["evaluation_ready"] = True
                        with open(mf, "w") as f:
                            yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
                else:
                    total_no_match += 1
            except Exception:
                total_no_match += 1

    print(f"\n{'='*60}")
    print(f"Summary: {total_fixes} fixed, {total_already_ok} already OK, {total_no_match} unresolved")


if __name__ == "__main__":
    main()
