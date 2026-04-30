"""Gate G1: rule baseline correctly classifies all 6 hand-authored PFGs.

Every VULNERABLE endpoint must be flagged with the right subtype; every SAFE
or INTENTIONALLY_PUBLIC endpoint must NOT be flagged.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pfg.detectors.rule_baseline import detect_all
from pfg.pfg.graph import load_pfg
from pfg.pfg.nodes import LabelKind

# (golden_name, expected_findings: dict[endpoint_id, expected_subtype])
EXPECTED: dict[str, dict[str, str]] = {
    "toy_safe": {},
    "toy_public": {},
    "toy_missing_auth": {"ep_dump_users": "MISSING_AUTH"},
    "toy_missing_role": {"ep_delete_user": "MISSING_ROLE"},
    "toy_idor": {"ep_get_account_tx": "IDOR"},
    # toy_combined endpoint is requires_auth=False AND has IDOR-style flow;
    # the endpoint label is COMBINED but the rule baseline is allowed to
    # report MISSING_AUTH alone (IDOR rule ignores requires_auth=False since
    # MISSING_AUTH already supersedes; we accept either MISSING_AUTH or both).
    "toy_combined": {"ep_update_profile": "MISSING_AUTH"},
}


@pytest.mark.parametrize("name,expected", EXPECTED.items())
def test_rule_baseline_classifies_golden(golden_dir: Path, name: str, expected: dict[str, str]) -> None:
    pfg = load_pfg(golden_dir / f"{name}.json")
    findings = detect_all(pfg)
    flagged: dict[str, set[str]] = {}
    for f in findings:
        flagged.setdefault(f.endpoint_id, set()).add(f.subtype.value)

    # All expected vulnerable endpoints flagged with at least the expected subtype.
    for ep_id, subtype in expected.items():
        assert ep_id in flagged, f"{name}: endpoint {ep_id} not flagged; got {flagged}"
        assert subtype in flagged[ep_id], (
            f"{name}: endpoint {ep_id} expected subtype {subtype}, got {flagged[ep_id]}"
        )

    # No SAFE or INTENTIONALLY_PUBLIC endpoint should be flagged.
    for ep_id, label in pfg.labels.items():
        kind = label.label.value if hasattr(label.label, "value") else label.label
        if kind in (LabelKind.SAFE.value, LabelKind.INTENTIONALLY_PUBLIC.value):
            assert ep_id not in flagged, (
                f"{name}: false positive on {kind} endpoint {ep_id}: {flagged.get(ep_id)}"
            )


def test_combined_endpoint_can_also_have_idor(golden_dir: Path) -> None:
    """Sanity: combined endpoint with no auth + identifier flow is still detected as IDOR by the IDOR rule."""
    pfg = load_pfg(golden_dir / "toy_combined.json")
    findings = detect_all(pfg)
    subs = {f.subtype.value for f in findings if f.endpoint_id == "ep_update_profile"}
    assert "MISSING_AUTH" in subs
    # IDOR is also detectable on top, since the rule is independent.
    assert "IDOR" in subs
