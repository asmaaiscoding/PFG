#!/usr/bin/env python3
"""Harvest Django/DRF authorization-related CVEs from GitHub Advisory Database.

Queries the GitHub Advisory REST API for Python/pip advisories matching
authorization-related CWEs and keywords, then filters for Django/DRF projects.

Usage:
    # With GitHub token (recommended — 5000 req/hr vs 60 unauthenticated):
    export GITHUB_TOKEN=ghp_...
    python scripts/harvest_advisories.py

    # Without token (slower, rate-limited):
    python scripts/harvest_advisories.py

Output:
    artifacts/advisory_candidates.json — full candidate list
    artifacts/advisory_candidates.csv  — summary for manual review
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# --- Configuration ---

# CWEs that map to authorization vulnerabilities
AUTH_CWES = [
    "CWE-639",   # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-862",   # Missing Authorization
    "CWE-863",   # Incorrect Authorization
    "CWE-284",   # Improper Access Control
    "CWE-285",   # Improper Authorization
    "CWE-269",   # Improper Privilege Management
    "CWE-732",   # Incorrect Permission Assignment
    "CWE-915",   # Improperly Controlled Modification of Dynamically-Determined Object Attributes
]

# Keywords to search in advisory descriptions (separate queries)
KEYWORD_QUERIES = [
    "IDOR django",
    "missing authorization django",
    "permission bypass django",
    "broken access control django",
    "insecure direct object",
    "authorization bypass django",
    "tenant isolation django",
    "object permission django",
    "access control django rest",
    "unauthorized access django",
]

# Django/DRF package names and keywords to filter results
DJANGO_INDICATORS = {
    # Package names
    "django", "djangorestframework", "drf", "wagtail", "nautobot",
    "netbox", "saleor", "weblate", "pretix", "sentry", "zulip",
    "taiga", "pulp", "wger", "ralph", "healthchecks", "paperless",
    "mayan", "reviewboard", "plane", "rdmo", "django-wiki",
    "django-mdeditor", "django-unicorn", "django-allauth",
    "django-rest-framework", "django-filter", "django-guardian",
    "django-oscar", "django-cms", "django-shop", "django-channels",
}

# Subtypes we care about (for classification)
SUBTYPE_KEYWORDS = {
    "IDOR": ["idor", "insecure direct object", "user-controlled key", "object reference"],
    "MISSING_AUTH": ["missing auth", "unauthenticated", "without authentication", "no authentication"],
    "MISSING_ROLE": ["privilege escalation", "role", "admin bypass", "staff", "superuser"],
    "TENANT_ISOLATION_FAILURE": ["tenant", "multi-tenant", "cross-tenant", "organization isolation"],
    "OBJECT_LEVEL_PERMISSION_BYPASS": ["object permission", "object-level", "per-object"],
}

# Output paths
OUTPUT_DIR = Path("artifacts")
OUTPUT_JSON = OUTPUT_DIR / "advisory_candidates.json"
OUTPUT_CSV = OUTPUT_DIR / "advisory_candidates.csv"


@dataclass
class AdvisoryCandidate:
    ghsa_id: str
    cve_id: str | None
    severity: str
    summary: str
    description: str
    package_name: str
    ecosystem: str
    vulnerable_range: str
    cwes: list[str]
    published_at: str
    updated_at: str
    html_url: str
    source_repo: str | None = None
    references: list[str] = field(default_factory=list)
    fix_commits: list[str] = field(default_factory=list)
    likely_subtype: str = "UNKNOWN"
    is_django_drf: bool = False
    notes: str = ""


def github_request(url: str, token: str | None = None) -> dict | list:
    """Make a GitHub API request with rate-limit handling."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = Request(url, headers=headers)
    for attempt in range(3):
        try:
            with urlopen(req) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                if remaining != "?" and int(remaining) < 5:
                    reset_time = int(resp.headers.get("X-RateLimit-Reset", "0"))
                    wait = max(0, reset_time - int(time.time())) + 2
                    print(f"  [rate-limit] {remaining} remaining, waiting {wait}s...")
                    time.sleep(wait)
                return json.loads(resp.read())
        except HTTPError as e:
            if e.code == 429:
                reset_time = int(e.headers.get("X-RateLimit-Reset", "0"))
                wait = max(0, reset_time - int(time.time())) + 5
                print(f"  [429] Rate limited. Waiting {wait}s (attempt {attempt+1}/3)...")
                time.sleep(wait)
            elif e.code == 403:
                reset_time = int(e.headers.get("X-RateLimit-Reset", "0"))
                wait = max(0, reset_time - int(time.time())) + 5
                print(f"  [403] Forbidden (likely rate limit). Waiting {wait}s...")
                time.sleep(wait)
            else:
                raise
    raise RuntimeError(f"Failed after 3 attempts: {url}")


def _paginate(base_url: str, params: dict, token: str | None, label: str, max_pages: int = 20) -> list[dict]:
    """Paginate through GitHub Advisory API results using Link-header cursors."""
    results = []
    url = f"{base_url}?{urlencode(params)}"
    page = 1
    while url and page <= max_pages:
        print(f"  Fetching {label} page {page}...")
        req = Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        })
        try:
            with urlopen(req) as resp:
                data = json.loads(resp.read())
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                if remaining != "?" and int(remaining) < 3:
                    reset_time = int(resp.headers.get("X-RateLimit-Reset", "0"))
                    wait = max(0, reset_time - int(time.time())) + 2
                    print(f"  [rate-limit] {remaining} remaining, waiting {wait}s...")
                    time.sleep(wait)
                # Parse Link header for next page cursor
                link_header = resp.headers.get("Link", "")
                next_url = None
                if link_header:
                    for part in link_header.split(","):
                        if 'rel="next"' in part:
                            next_url = part.split("<")[1].split(">")[0]
                            break
        except HTTPError as e:
            if e.code == 429 or e.code == 403:
                reset_time = int(e.headers.get("X-RateLimit-Reset", "0"))
                wait = max(0, reset_time - int(time.time())) + 10
                print(f"  [{e.code}] Rate limited. Waiting {wait}s...")
                time.sleep(wait)
                continue
            else:
                print(f"  ERROR: {e}")
                break

        if not data:
            break
        results.extend(data)
        if len(data) < int(params.get("per_page", 100)) or not next_url:
            break
        url = next_url
        page += 1
        time.sleep(0.5)

    return results


def fetch_advisories_by_package(package: str, token: str | None) -> list[dict]:
    """Fetch all advisories affecting a specific pip package."""
    params = {
        "ecosystem": "pip",
        "type": "reviewed",
        "affects": package,
        "per_page": "100",
        "sort": "published",
        "direction": "desc",
    }
    return _paginate("https://api.github.com/advisories", params, token, f"pkg:{package}")


def fetch_all_pip_advisories(token: str | None, max_pages: int = 10) -> list[dict]:
    """Fetch recent pip advisories (bulk, for keyword filtering)."""
    params = {
        "ecosystem": "pip",
        "type": "reviewed",
        "per_page": "100",
        "sort": "published",
        "direction": "desc",
    }
    return _paginate("https://api.github.com/advisories", params, token, "all-pip", max_pages=max_pages)


def _ref_to_url(ref) -> str:
    """Extract URL from a reference (can be str or dict)."""
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return ref.get("url", "")
    return ""


def extract_fix_commits(references: list) -> list[str]:
    """Extract fix commit URLs from advisory references."""
    commits = []
    for ref in references:
        url = _ref_to_url(ref)
        if "/commit/" in url or "/commits/" in url:
            commits.append(url)
        elif "/pull/" in url and "/commits" not in url:
            commits.append(url)
    return commits


def extract_source_repo(vulnerabilities: list[dict], references: list) -> str | None:
    """Try to determine the source repository URL."""
    # From vulnerability package source_code_location
    for vuln in vulnerabilities:
        pkg = vuln.get("package", {})
        source = pkg.get("source_code_location")
        if source:
            return source

    # From references
    for ref in references:
        url = _ref_to_url(ref)
        if "github.com" in url and ("/commit/" in url or "/security/" in url or "/pull/" in url):
            parts = url.split("github.com/")[1].split("/")
            if len(parts) >= 2:
                return f"https://github.com/{parts[0]}/{parts[1]}"
    return None


def classify_subtype(summary: str, description: str, cwes: list[str]) -> str:
    """Heuristic classification of vulnerability subtype."""
    text = f"{summary} {description}".lower()

    # Check CWE first
    if "CWE-639" in cwes:
        return "IDOR"
    if "CWE-862" in cwes:
        return "MISSING_AUTH"

    # Keyword matching
    for subtype, keywords in SUBTYPE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return subtype

    # Fallback heuristics
    if "permission" in text and "bypass" in text:
        return "OBJECT_LEVEL_PERMISSION_BYPASS"
    if "access control" in text:
        return "IDOR"  # Most common mapping
    if "unauthorized" in text:
        return "MISSING_AUTH"

    return "UNKNOWN"


def is_django_project(advisory: dict) -> bool:
    """Check if the advisory is for a Django/DRF project."""
    # Check package name
    vulnerabilities = advisory.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        pkg_name = vuln.get("package", {}).get("name", "").lower()
        if any(indicator in pkg_name for indicator in DJANGO_INDICATORS):
            return True

    # Check description for Django/DRF mentions
    text = f"{advisory.get('summary', '')} {advisory.get('description', '')}".lower()
    django_terms = ["django", "drf", "rest_framework", "rest framework", "viewset",
                    "apiview", "serializer", "modelviewset", "genericapiview"]
    if any(term in text for term in django_terms):
        return True

    # Check references for Django-related repos
    references = advisory.get("references", [])
    for ref in references:
        url = _ref_to_url(ref).lower()
        if any(f"/{ind}" in url or f"/{ind}/" in url for ind in DJANGO_INDICATORS):
            return True

    return False


def process_advisory(advisory: dict) -> AdvisoryCandidate | None:
    """Convert a raw advisory API response to a candidate."""
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id")
    severity = advisory.get("severity", "unknown")
    summary = advisory.get("summary", "")
    description = advisory.get("description", "")[:2000]  # Truncate long descriptions
    published_at = advisory.get("published_at", "")
    updated_at = advisory.get("updated_at", "")
    html_url = advisory.get("html_url", "")
    raw_cwes = advisory.get("cwes", [])
    cwes = []
    for c in raw_cwes:
        if isinstance(c, str):
            cwes.append(c)
        elif isinstance(c, dict):
            cwes.append(c.get("cwe_id", ""))
    references = advisory.get("references", [])
    vulnerabilities = advisory.get("vulnerabilities", [])

    # Get package info from first vulnerability entry
    package_name = ""
    ecosystem = "pip"
    vulnerable_range = ""
    if vulnerabilities:
        first = vulnerabilities[0]
        package_name = first.get("package", {}).get("name", "")
        ecosystem = first.get("package", {}).get("ecosystem", "pip")
        vulnerable_range = first.get("vulnerable_version_range", "")

    # Extract metadata
    fix_commits = extract_fix_commits(references)
    source_repo = extract_source_repo(vulnerabilities, references)
    ref_urls = [_ref_to_url(r) for r in references]

    # Classification
    likely_subtype = classify_subtype(summary, description, cwes)
    django = is_django_project(advisory)

    return AdvisoryCandidate(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        severity=severity,
        summary=summary,
        description=description,
        package_name=package_name,
        ecosystem=ecosystem,
        vulnerable_range=vulnerable_range,
        cwes=cwes,
        published_at=published_at,
        updated_at=updated_at,
        html_url=html_url,
        source_repo=source_repo,
        references=ref_urls,
        fix_commits=fix_commits,
        likely_subtype=likely_subtype,
        is_django_drf=django,
    )


def deduplicate(candidates: list[AdvisoryCandidate]) -> list[AdvisoryCandidate]:
    """Deduplicate by GHSA ID."""
    seen: dict[str, AdvisoryCandidate] = {}
    for c in candidates:
        if c.ghsa_id not in seen:
            seen[c.ghsa_id] = c
    return list(seen.values())


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("WARNING: No GITHUB_TOKEN set. Rate limited to 60 req/hr.")
        print("         Set GITHUB_TOKEN=ghp_... for 5000 req/hr.\n")
    else:
        print("Using GitHub token for authenticated requests.\n")

    all_candidates: list[AdvisoryCandidate] = []

    # --- Phase 1: Query per known Django/DRF package ---
    # High-yield packages first (known to have authz CVEs), then broader
    DJANGO_PACKAGES = [
        # Priority 1: Known high-yield Django/DRF projects with authz CVEs
        "wger", "nautobot", "weblate", "pretix", "wagtail", "saleor",
        "mayan-edms", "django-mdeditor", "plane", "pulpcore",
        # Priority 2: Broader Django ecosystem
        "django", "djangorestframework", "django-allauth",
        "django-unicorn", "reviewboard", "django-oscar",
        "django-cms", "label-studio", "defectdojo",
        "authentik", "netbox", "sentry-sdk",
    ]

    print("=== Phase 1: Querying per Django/DRF package ===")
    for pkg in DJANGO_PACKAGES:
        print(f"\n[Package] {pkg}")
        try:
            advisories = fetch_advisories_by_package(pkg, token)
            print(f"  Found {len(advisories)} advisories")
            for adv in advisories:
                candidate = process_advisory(adv)
                if candidate:
                    all_candidates.append(candidate)
        except Exception as e:
            print(f"  ERROR: {e}")
        time.sleep(1)  # Be polite between queries

    # --- Phase 2: Bulk fetch recent pip advisories and filter locally ---
    print("\n=== Phase 2: Bulk fetch + local keyword filter ===")
    try:
        # Fetch up to 10 pages (1000 most recent pip advisories)
        all_pip = fetch_all_pip_advisories(token, max_pages=10)
        print(f"  Fetched {len(all_pip)} total pip advisories")

        # Filter locally by authorization keywords in summary/description
        auth_keywords = [
            "authorization", "permission", "access control", "idor",
            "insecure direct object", "privilege", "tenant", "unauthorized",
            "broken access", "object-level", "missing auth", "role bypass",
        ]
        for adv in all_pip:
            text = f"{adv.get('summary', '')} {adv.get('description', '')}".lower()
            if any(kw in text for kw in auth_keywords):
                candidate = process_advisory(adv)
                if candidate:
                    all_candidates.append(candidate)
    except Exception as e:
        print(f"  ERROR: {e}")

    # --- Deduplicate ---
    all_candidates = deduplicate(all_candidates)
    print(f"\n=== Total unique advisories: {len(all_candidates)} ===")

    # --- Filter: Django/DRF only ---
    django_candidates = [c for c in all_candidates if c.is_django_drf]
    print(f"=== Django/DRF advisories: {len(django_candidates)} ===")

    # --- Filter: Authorization-related (has auth subtype or auth CWE) ---
    auth_candidates = [
        c for c in django_candidates
        if c.likely_subtype != "UNKNOWN" or any(cwe in AUTH_CWES for cwe in c.cwes)
    ]
    # Also include unknowns that mention authorization in description
    for c in django_candidates:
        if c not in auth_candidates:
            text = f"{c.summary} {c.description}".lower()
            auth_terms = ["authorization", "permission", "access control", "idor",
                         "privilege", "tenant", "unauthorized", "broken access"]
            if any(t in text for t in auth_terms):
                auth_candidates.append(c)
    auth_candidates = deduplicate(auth_candidates)

    print(f"=== Authorization-specific: {len(auth_candidates)} ===")

    # --- Sort by quality (has fix commit, has CVE, recent first) ---
    def quality_score(c: AdvisoryCandidate) -> tuple:
        return (
            bool(c.fix_commits),        # Has fix commit
            bool(c.cve_id),             # Has CVE ID
            bool(c.source_repo),        # Has source repo
            c.published_at or "",       # Recent first
        )

    auth_candidates.sort(key=quality_score, reverse=True)

    # --- Also output ALL Django advisories (some we marked UNKNOWN might be useful) ---
    django_candidates.sort(key=quality_score, reverse=True)

    # --- Output ---
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # JSON output (full data — all Django candidates, not just auth-filtered)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump([asdict(c) for c in django_candidates], f, indent=2, ensure_ascii=False)
    print(f"\nFull Django data written to: {OUTPUT_JSON}")

    # CSV output (auth-filtered summary for review)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ghsa_id", "cve_id", "package", "severity", "subtype",
            "summary", "source_repo", "has_fix_commit", "published",
        ])
        for c in auth_candidates:
            writer.writerow([
                c.ghsa_id,
                c.cve_id or "",
                c.package_name,
                c.severity,
                c.likely_subtype,
                c.summary[:120],
                c.source_repo or "",
                "yes" if c.fix_commits else "no",
                c.published_at[:10] if c.published_at else "",
            ])
    print(f"Summary CSV written to: {OUTPUT_CSV}")

    # --- Print summary stats ---
    print("\n=== SUMMARY ===")
    print(f"Total unique pip advisories found: {len(all_candidates)}")
    print(f"Django/DRF specific: {len(django_candidates)}")
    print(f"Authorization-related Django/DRF: {len(auth_candidates)}")
    print()

    # By subtype
    from collections import Counter
    subtype_counts = Counter(c.likely_subtype for c in auth_candidates)
    print("By likely subtype:")
    for subtype, count in subtype_counts.most_common():
        print(f"  {subtype}: {count}")

    # By package
    pkg_counts = Counter(c.package_name for c in auth_candidates)
    print("\nBy package (top 20):")
    for pkg, count in pkg_counts.most_common(20):
        print(f"  {pkg}: {count}")

    # Quality indicators
    with_fix = sum(1 for c in auth_candidates if c.fix_commits)
    with_cve = sum(1 for c in auth_candidates if c.cve_id)
    with_repo = sum(1 for c in auth_candidates if c.source_repo)
    print(f"\nQuality indicators:")
    print(f"  Has fix commit: {with_fix}/{len(auth_candidates)}")
    print(f"  Has CVE ID: {with_cve}/{len(auth_candidates)}")
    print(f"  Has source repo: {with_repo}/{len(auth_candidates)}")

    # Already in our benchmark
    existing = {"wger", "nautobot", "sentry", "weblate", "pretix", "django-mdeditor"}
    new_pkgs = [c for c in auth_candidates if c.package_name.lower() not in existing]
    print(f"\n  New packages (not in current benchmark): {len(new_pkgs)}")
    print(f"  From existing packages (potential additions): {len(auth_candidates) - len(new_pkgs)}")

    # Top candidates for immediate addition
    print("\n=== TOP CANDIDATES FOR BENCHMARK (have fix + CVE + repo) ===")
    top = [c for c in auth_candidates if c.fix_commits and c.cve_id and c.source_repo]
    for i, c in enumerate(top[:30], 1):
        status = "EXISTING" if c.package_name.lower() in existing else "NEW"
        print(f"  {i:2d}. [{status}] {c.cve_id} ({c.package_name}) — {c.likely_subtype}")
        print(f"      {c.summary[:100]}")
        print(f"      repo: {c.source_repo}")
        print()


if __name__ == "__main__":
    main()
