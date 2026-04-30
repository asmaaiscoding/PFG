"""Frozen feature-encoder snapshot tests."""
from __future__ import annotations

from pathlib import Path

from pfg.pfg.features import EDGE_FEATURE_DIM, NODE_FEATURE_DIM, encode_edge, encode_node
from pfg.pfg.graph import load_pfg


def test_node_feature_dim(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
    for n in pfg.nodes:
        v = encode_node(n)
        assert len(v) == NODE_FEATURE_DIM
        assert all(0.0 <= x <= 1.0 for x in v)


def test_endpoint_feature_snapshot(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
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


def test_data_access_feature_snapshot(golden_dir: Path) -> None:
    pfg = load_pfg(golden_dir / "toy_idor.json")
    da = next(n for n in pfg.nodes if n.id == "da_tx_read")
    v = encode_node(da)
    # node_type=data_access
    assert v[0:4] == [0.0, 0.0, 0.0, 1.0]
    # op=READ
    assert v[19:23] == [1.0, 0.0, 0.0, 0.0]
    # has_ownership_predicate=False
    assert v[23] == 0.0


def test_edge_feature() -> None:
    assert encode_edge("call") == [1.0, 0.0]
    assert encode_edge("identifier_flow") == [0.0, 1.0]
    assert EDGE_FEATURE_DIM == 2
