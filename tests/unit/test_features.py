"""Frozen feature-encoder snapshot tests."""
from __future__ import annotations

from pathlib import Path

from pfg.pfg.features import (
    EDGE_FEATURE_DIM,
    NODE_FEATURE_DIM,
    encode_edge,
    encode_node,
    enrich_endpoint_features,
)
from pfg.pfg.graph import load_pfg


def test_node_feature_dim(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
    enrich_endpoint_features(pfg)
    for n in pfg.nodes:
        v = encode_node(n)
        assert len(v) == NODE_FEATURE_DIM
        assert all(0.0 <= x <= 1.0 for x in v)


def test_endpoint_feature_snapshot(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
    enrich_endpoint_features(pfg)
    ep = next(n for n in pfg.nodes if n.id == "ep_get_account_tx")
    v = encode_node(ep)
    # node_type=endpoint
    assert v[0:4] == [1.0, 0.0, 0.0, 0.0]
    # http=GET
    assert v[4:9] == [1.0, 0.0, 0.0, 0.0, 0.0]
    # requires_auth=True
    assert v[9] == 1.0
    # role=USER
    assert v[10:15] == [0.0, 1.0, 0.0, 0.0, 0.0]
    # ownership_check_present=False
    assert v[15] == 0.0
    # has_route_params=True (route_params=['tx_id'])
    assert v[24] == 1.0
    # has_id_flow=True (identifier_flow edge exists from this endpoint)
    assert v[26] == 1.0
    # unprotected_data_reachable=True (da_tx_read has_ownership_predicate=False)
    assert v[27] == 1.0


def test_data_access_feature_snapshot(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
    enrich_endpoint_features(pfg)
    da = next(n for n in pfg.nodes if n.id == "da_tx_read")
    v = encode_node(da)
    # node_type=data_access
    assert v[0:4] == [0.0, 0.0, 0.0, 1.0]
    # op=READ
    assert v[19:23] == [1.0, 0.0, 0.0, 0.0]
    # has_ownership_predicate=False
    assert v[23] == 0.0
    # non-endpoint nodes get zeros for endpoint structural features
    assert v[24:35] == [0.0] * 11


def test_edge_feature() -> None:
    assert encode_edge("call") == [1.0, 0.0, 0.0]
    assert encode_edge("identifier_flow") == [0.0, 1.0, 0.0]
    assert encode_edge("tenant_flow") == [0.0, 0.0, 1.0]
    assert EDGE_FEATURE_DIM == 3
