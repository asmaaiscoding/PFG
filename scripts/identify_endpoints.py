#!/usr/bin/env python3
"""
Run the Spring extractor on fetched Java benchmarks and identify vulnerable endpoints.

For each manifest with a `fixed_commit`, fetches the commit diff from GitHub API,
identifies which Java file/endpoint was changed, and maps it to the extracted endpoint_id.

Usage:
    python scripts/identify_endpoints.py [--update-manifests]
"""
import json
import os
import re
import sys
import urllib.request
import yaml
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pfg.extractors.spring.build import build_pfg, discover_endpoints, _safe_id

CORPUS_ROOT = Path("benchmarks/realworld")
TOKEN = os.environ.get("GITHUB_TOKEN", "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")


def github_api(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
    })
    resp = urllib.request.urlopen(req, timeout=30)
    return json.loads(resp.read())


def get_commit_diff_files(repo: str, sha: str) -> list[dict]:
    """Get list of files changed in a commit."""
    try:
        data = github_api(f"https://api.github.com/repos/{repo}/commits/{sha}")
        return data.get("files", [])
    except Exception as e:
        print(f"    [warn] Could not fetch diff for {sha[:10]}: {e}")
        return []


def extract_endpoint_hints_from_diff(files: list[dict]) -> list[str]:
    """Extract route/endpoint hints from a commit diff.
    
    Looks for:
    - Added @PreAuthorize / @Secured / @RolesAllowed annotations
    - Modified controller/resource files
    - Route patterns in the patch text
    """
    hints = []
    route_pattern = re.compile(r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)')
    jaxrs_path = re.compile(r'@Path\s*\(\s*["\']([^"\']+)')
    
    for f in files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        
        # Only look at Java files
        if not filename.endswith(".java"):
            continue
        
        # Extract class name from path
        class_name = filename.rsplit("/", 1)[-1].replace(".java", "")
        
        # Look for route patterns in added lines
        for line in patch.split("\n"):
            if not line.startswith("+"):
                continue
            # Spring MVC routes
            m = route_pattern.search(line)
            if m:
                hints.append(m.group(1))
            # JAX-RS paths
            m = jaxrs_path.search(line)
            if m:
                hints.append(m.group(1))
        
        # Add class hint for ALL Java source files (not just tests)
        if "test" not in class_name.lower() and "Test" not in filename.split("/")[-2:][0]:
            hints.append(f"CLASS:{class_name}")
    
    return hints


def match_endpoint_to_hints(endpoints: list, hints: list[str], manifest_data: dict) -> str | None:
    """Try to match an extracted endpoint to the vulnerability hints from the diff.
    
    Returns the endpoint_id if found, None otherwise.
    """
    if not hints:
        return None
    
    route_hints = [h for h in hints if not h.startswith("CLASS:")]
    class_hints = [h.replace("CLASS:", "") for h in hints if h.startswith("CLASS:")]
    
    best_match = None
    best_score = 0
    
    for ep, _, _ in endpoints:
        score = 0
        
        # Match by route
        for hint in route_hints:
            # Normalize routes for comparison
            ep_route = ep.route.lower().rstrip("/")
            hint_route = hint.lower().rstrip("/")
            if hint_route in ep_route or ep_route in hint_route:
                score += 10
            elif any(seg in ep_route for seg in hint_route.split("/") if seg and seg != "api"):
                score += 3
        
        # Match by class name
        for cls in class_hints:
            if cls.lower() in ep.handler_qualname.lower():
                score += 5
        
        # Penalize OPTIONS/HEAD (less likely to be the vulnerable endpoint)
        if ep.http_method in ("OPTIONS", "HEAD"):
            score -= 2
        
        if score > best_score:
            best_score = score
            best_match = ep
    
    if best_match and best_score >= 3:
        eid = _safe_id(f"endpoint__{best_match.http_method}__{best_match.route}")
        return eid
    
    return None


def main():
    update_manifests = "--update-manifests" in sys.argv
    
    manifests = []
    for mpath in sorted(CORPUS_ROOT.glob("*/manifest.yaml")):
        if mpath.parent.name == "_template":
            continue
        try:
            data = yaml.safe_load(mpath.read_text())
            if data.get("framework") != "spring":
                continue
            manifests.append((mpath, data))
        except Exception:
            continue
    
    print(f"Java manifests: {len(manifests)}")
    print("=" * 70)
    
    results = []
    
    for mpath, data in manifests:
        app_name = mpath.parent.name
        checkout_dir = data.get("checkout_dir", "src")
        source_subdir = data.get("source_subdir", "")
        target_path = mpath.parent / checkout_dir
        
        if not target_path.exists():
            print(f"\n{app_name}: NOT FETCHED")
            continue
        
        # Determine where to run extractor
        # If source_subdir exists, use it as a subdirectory of the checkout
        if source_subdir:
            extract_root = target_path / source_subdir
        else:
            extract_root = target_path
        
        if not extract_root.exists():
            print(f"\n{app_name}: source_subdir not found: {source_subdir}")
            continue
        
        print(f"\n{'─' * 70}")
        print(f"{app_name}")
        print(f"  Source: {extract_root.relative_to(mpath.parent)}")
        
        # Run extractor
        try:
            pfg = build_pfg(extract_root, application=app_name)
            endpoint_nodes = [n for n in pfg.nodes if n.type == "endpoint"]
            print(f"  Endpoints found: {len(endpoint_nodes)}")
            
            if not endpoint_nodes:
                print(f"  ⚠ No endpoints extracted!")
                results.append({"app": app_name, "endpoints": 0, "matched": None})
                continue
            
            # Show first 5 endpoints
            for n in endpoint_nodes[:5]:
                attrs = n.attrs
                auth = "🔒" if getattr(attrs, 'requires_auth', False) else "🔓"
                role = getattr(attrs, 'required_role', 'NONE')
                route = getattr(attrs, 'route', '?')
                method = getattr(attrs, 'http_method', '?')
                print(f"    {auth} {method:6} {route} [role={role}]")
            if len(endpoint_nodes) > 5:
                print(f"    ... and {len(endpoint_nodes) - 5} more")
            
        except Exception as e:
            print(f"  ✗ Extraction failed: {e}")
            results.append({"app": app_name, "endpoints": -1, "matched": None, "error": str(e)})
            continue
        
        # Try to identify the vulnerable endpoint from the fix commit
        fixed_commit = data.get("fixed_commit", "")
        repo_url = data.get("repo_url", "")
        matched_id = None
        
        if fixed_commit and repo_url:
            parts = repo_url.rstrip("/").split("/")
            repo = f"{parts[-2]}/{parts[-1]}"
            
            diff_files = get_commit_diff_files(repo, fixed_commit)
            if diff_files:
                hints = extract_endpoint_hints_from_diff(diff_files)
                if hints:
                    print(f"  Fix commit hints: {hints[:5]}")
                    # Get raw endpoints for matching
                    try:
                        raw_eps = list(discover_endpoints(extract_root))
                        matched_id = match_endpoint_to_hints(raw_eps, hints, data)
                    except Exception:
                        pass
                
                if not matched_id:
                    # Fallback: find endpoints in files touched by the fix
                    touched_classes = []
                    for f in diff_files:
                        fname = f.get("filename", "")
                        if fname.endswith(".java"):
                            cls = fname.rsplit("/", 1)[-1].replace(".java", "")
                            touched_classes.append(cls)
                    
                    if touched_classes:
                        # Collect ALL candidates from touched classes, prefer non-OPTIONS/HEAD
                        candidates = []
                        for n in endpoint_nodes:
                            source_loc = getattr(n.attrs, 'source_location', '') or ''
                            method = getattr(n.attrs, 'http_method', '')
                            for cls in touched_classes:
                                if cls in source_loc or cls in n.id:
                                    # Rank: prefer GET/POST/PUT/DELETE/PATCH over OPTIONS/HEAD
                                    priority = 0 if method in ('OPTIONS', 'HEAD') else 1
                                    candidates.append((priority, n.id))
                                    break
                        if candidates:
                            candidates.sort(key=lambda x: -x[0])
                            matched_id = candidates[0][1]
        
        if matched_id:
            print(f"  ✓ Matched endpoint: {matched_id}")
            # Find the endpoint details
            for n in endpoint_nodes:
                if n.id == matched_id:
                    route = getattr(n.attrs, 'route', '?')
                    method = getattr(n.attrs, 'http_method', '?')
                    print(f"    → {method} {route}")
                    break
        else:
            print(f"  ? Could not match vulnerable endpoint")
        
        results.append({
            "app": app_name,
            "endpoints": len(endpoint_nodes),
            "matched": matched_id,
        })
        
        # Update manifest if requested
        if update_manifests and matched_id:
            # Update the endpoint_id in expected_findings
            findings = data.get("expected_findings", [])
            if findings and findings[0].get("endpoint_id", "").startswith("endpoint__cve"):
                findings[0]["endpoint_id"] = matched_id
                data["expected_findings"] = findings
                mpath.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True))
                print(f"  📝 Updated manifest")
    
    # Summary
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"  Total: {len(results)}")
    print(f"  Extracted OK: {sum(1 for r in results if r['endpoints'] > 0)}")
    print(f"  No endpoints: {sum(1 for r in results if r['endpoints'] == 0)}")
    print(f"  Failed: {sum(1 for r in results if r['endpoints'] < 0)}")
    print(f"  Matched endpoint: {sum(1 for r in results if r.get('matched'))}")
    print(f"  Unmatched: {sum(1 for r in results if r['endpoints'] > 0 and not r.get('matched'))}")


if __name__ == "__main__":
    main()
