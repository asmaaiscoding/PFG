"""Phase 4 W21: Semgrep / CodeQL adapter tests."""
from __future__ import annotations

import json
from pathlib import Path

from pfg.eval.external import (
    _endpoint_locations,
    _resolve_endpoint,
    _to_subtype,
    normalize_codeql,
    normalize_semgrep,
    write_normalized,
)
from pfg.extractors.django.build import build_pfg

REF_MIN = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_min"


def test_endpoint_locations_extracts_endpoints_with_source_loc() -> None:
    pfg = build_pfg(REF_MIN, application="ref_min")
    locs = _endpoint_locations(pfg)
    # ref_min has 11 endpoints, all with source locations.
    assert len(locs) >= 1
    # All entries must be (file_str, int_line, ep_id) triples.
    for fp, line, eid in locs:
        assert isinstance(fp, str) and fp.endswith(".py")
        assert isinstance(line, int) and line > 0
        assert eid.startswith("endpoint__")


def test_resolve_endpoint_picks_closest_above() -> None:
    locs = [
        ("apps/views.py", 10, "ep_a"),
        ("apps/views.py", 50, "ep_b"),
        ("apps/views.py", 100, "ep_c"),
    ]
    # Finding at line 60 should map to ep_b (closest above).
    assert _resolve_endpoint(locs, "apps/views.py", 60) == "ep_b"
    # Finding at line 5 (above the first endpoint) should still resolve via window.
    assert _resolve_endpoint(locs, "apps/views.py", 5) == "ep_a"
    # Finding in unrelated file -> None.
    assert _resolve_endpoint(locs, "apps/other.py", 60) is None


def test_to_subtype_exact_and_substring() -> None:
    mapping = {"py/missing-authorization": "MISSING_ROLE", "cwe-639": "IDOR"}
    assert _to_subtype("py/missing-authorization", mapping) == "MISSING_ROLE"
    # Substring match (case-insensitive).
    assert _to_subtype("CWE-639/some/variant", mapping) == "IDOR"
    assert _to_subtype("unknown.rule", mapping) is None


def test_normalize_semgrep_end_to_end(tmp_path: Path) -> None:
    pfg = build_pfg(REF_MIN, application="ref_min")
    locs = _endpoint_locations(pfg)
    assert locs, "ref_min must have at least one located endpoint"
    file_path, lineno, expected_ep = locs[0]

    semgrep_payload = {
        "results": [
            {
                "check_id": "python.django.security.audit.missing-authentication",
                "path": file_path,
                "start": {"line": lineno + 2, "col": 4},
            },
            # Unknown rule -> dropped.
            {"check_id": "irrelevant.rule", "path": file_path, "start": {"line": lineno}},
        ]
    }
    p = tmp_path / "semgrep.json"
    p.write_text(json.dumps(semgrep_payload), encoding="utf-8")

    out = normalize_semgrep(p, pfg)
    assert out == [{"endpoint_id": expected_ep, "subtype": "MISSING_AUTH"}]


def test_normalize_codeql_sarif(tmp_path: Path) -> None:
    pfg = build_pfg(REF_MIN, application="ref_min")
    locs = _endpoint_locations(pfg)
    file_path, lineno, expected_ep = locs[0]

    sarif_payload = {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "py/missing-authorization",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file_path},
                                    "region": {"startLine": lineno + 1},
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }
    p = tmp_path / "codeql.sarif.json"
    p.write_text(json.dumps(sarif_payload), encoding="utf-8")

    out = normalize_codeql(p, pfg)
    assert out == [{"endpoint_id": expected_ep, "subtype": "MISSING_ROLE"}]


def test_write_normalized_round_trip(tmp_path: Path) -> None:
    records = [{"endpoint_id": "ep_x", "subtype": "IDOR"}]
    out = write_normalized(records, tmp_path / "out.json")
    assert json.loads(out.read_text(encoding="utf-8")) == records
