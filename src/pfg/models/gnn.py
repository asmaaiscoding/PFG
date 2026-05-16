"""GNN models for PFG (Phase 3 W13-W14).

Two architectures contribute jointly to the thesis:

  Model A (Anomaly Detector)
    Graph-level binary classifier: vulnerable vs not.
    Backbone: GINEConv stack -> global mean+max pool -> MLP head.

  Model B (Path Analyzer)
    Graph + target-node-aware multi-class classifier over the configured
    access-control taxonomy.
    Backbone: GATv2Conv stack -> attention pool around target endpoint
    -> MLP head over the joint (target, graph) representation.

Both consume the same `Data` produced by `pfg.synthetic.dataset.pfg_to_pyg`,
which guarantees a consistent node + edge feature contract.

Implementation notes
--------------------
* Models depend on torch + torch_geometric. They live behind `if TYPE_CHECKING`
  imports so the module remains importable when those are absent (CLI users
  don't need to load torch just to run rule-baseline detection).
* The forward signatures accept either a single `Data` or a `Batch`.
* No training utilities here; see `pfg.training` for the loop.
"""

from __future__ import annotations

from pfg.pfg.features import EDGE_FEATURE_DIM, NODE_FEATURE_DIM

try:
    import torch
    from torch import nn
    from torch.nn import functional as F  # noqa: N812
    from torch_geometric.nn import GATv2Conv, GINEConv, global_max_pool, global_mean_pool

    _TORCH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TORCH_AVAILABLE = False


__all__ = [
    "EDGE_FEATURE_DIM",
    "NODE_FEATURE_DIM",
    "PathAnalyzer",
    "PfgAnomalyDetector",
    "torch_available",
]


def torch_available() -> bool:
    return _TORCH_AVAILABLE


if _TORCH_AVAILABLE:

    def _mlp(in_dim: int, hidden: int, out_dim: int, *, dropout: float = 0.1) -> nn.Module:
        return nn.Sequential(
            nn.Linear(in_dim, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, out_dim),
        )

    class PfgAnomalyDetector(nn.Module):
        """Model A — graph-level binary classifier (vulnerable vs benign).

        Architecture:
          Linear projection (NODE_FEATURE_DIM -> H)
          [GINEConv(H, H) + ReLU + Dropout] x num_layers, edge_dim=2
          mean+max pool -> Linear(2H -> 2)
        """

        def __init__(
            self,
            *,
            hidden_dim: int = 64,
            num_layers: int = 3,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            self.input = nn.Linear(NODE_FEATURE_DIM, hidden_dim)
            self.convs = nn.ModuleList()
            for _ in range(num_layers):
                inner = nn.Sequential(
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.ReLU(),
                    nn.Linear(hidden_dim, hidden_dim),
                )
                self.convs.append(GINEConv(inner, edge_dim=EDGE_FEATURE_DIM))
            self.dropout = nn.Dropout(dropout)
            self.head = _mlp(2 * hidden_dim, hidden_dim, 2, dropout=dropout)

        def forward(self, data) -> torch.Tensor:  # type: ignore[no-untyped-def]
            x, edge_index, edge_attr = data.x, data.edge_index, data.edge_attr
            batch = getattr(data, "batch", None)
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)

            h = self.input(x)
            for conv in self.convs:
                h = F.relu(conv(h, edge_index, edge_attr))
                h = self.dropout(h)
            g = torch.cat([global_mean_pool(h, batch), global_max_pool(h, batch)], dim=1)
            out: torch.Tensor = self.head(g)
            return out

    class PathAnalyzer(nn.Module):
        """Model B — target-aware multi-class subtype classifier.

        Architecture:
          Linear (NODE_FEATURE_DIM -> H)
          [GATv2Conv(H -> H, heads=4 -> concat -> H projection)] x num_layers
          attention pool around target endpoint:
            score_i = w^T tanh(W [h_i ; h_target])
            softmax over batch -> weighted sum
          head: Linear(2H -> H) -> ReLU -> Linear(H -> num_classes)
        """

        def __init__(
            self,
            *,
            hidden_dim: int = 64,
            num_layers: int = 3,
            heads: int = 4,
            num_classes: int = 8,
            dropout: float = 0.1,
        ) -> None:
            super().__init__()
            self.input = nn.Linear(NODE_FEATURE_DIM, hidden_dim)
            self.convs = nn.ModuleList()
            for _ in range(num_layers):
                self.convs.append(
                    GATv2Conv(
                        hidden_dim,
                        hidden_dim // heads,
                        heads=heads,
                        edge_dim=EDGE_FEATURE_DIM,
                        concat=True,
                    )
                )
            self.dropout = nn.Dropout(dropout)
            # Attention scorer over (h_i ; h_target) pairs.
            self.attn = nn.Sequential(
                nn.Linear(2 * hidden_dim, hidden_dim),
                nn.Tanh(),
                nn.Linear(hidden_dim, 1),
            )
            self.head = _mlp(2 * hidden_dim, hidden_dim, num_classes, dropout=dropout)

        def _encode_with_attention(self, data):  # type: ignore[no-untyped-def]
            x, edge_index, edge_attr = data.x, data.edge_index, data.edge_attr
            batch = getattr(data, "batch", None)
            if batch is None:
                batch = torch.zeros(x.size(0), dtype=torch.long, device=x.device)
            target_mask = data.target_mask  # (N,) float in {0,1}

            h = self.input(x)
            for conv in self.convs:
                h = F.elu(conv(h, edge_index, edge_attr))
                h = self.dropout(h)

            # Per-graph target representation: mean of h_i where target_mask=1.
            num_graphs = int(batch.max().item()) + 1
            h_target = _masked_mean_per_graph(h, target_mask, batch, num_graphs)

            # Broadcast h_target back to each node by its graph index.
            h_target_per_node = h_target[batch]  # (N, H)
            scored = self.attn(torch.cat([h, h_target_per_node], dim=1)).squeeze(-1)
            attn = _segment_softmax(scored, batch, num_graphs)
            pooled = _segment_weighted_sum(h, attn, batch, num_graphs)

            g = torch.cat([pooled, h_target], dim=1)
            return g, attn

        def forward(self, data) -> torch.Tensor:  # type: ignore[no-untyped-def]
            g, _ = self._encode_with_attention(data)  # type: ignore[no-untyped-call]
            out: torch.Tensor = self.head(g)
            return out

        def forward_with_attention(self, data) -> tuple[torch.Tensor, torch.Tensor]:  # type: ignore[no-untyped-def]
            """Return logits plus target-aware node attention weights."""
            g, attn = self._encode_with_attention(data)  # type: ignore[no-untyped-call]
            out: torch.Tensor = self.head(g)
            return out, attn

    # --- pooling helpers ------------------------------------------------

    def _masked_mean_per_graph(
        h: torch.Tensor, mask: torch.Tensor, batch: torch.Tensor, num_graphs: int
    ) -> torch.Tensor:
        """For each graph, mean of h[i] where mask[i]==1; falls back to graph mean."""
        out = h.new_zeros((num_graphs, h.size(1)))
        counts = h.new_zeros((num_graphs,))
        idx = batch.unsqueeze(-1).expand(-1, h.size(1))
        out.scatter_add_(0, idx, h * mask.unsqueeze(-1))
        counts.scatter_add_(0, batch, mask)
        # Fallback to plain mean if no target nodes flagged.
        plain_out = h.new_zeros((num_graphs, h.size(1)))
        plain_count = h.new_zeros((num_graphs,))
        plain_out.scatter_add_(0, idx, h)
        plain_count.scatter_add_(0, batch, torch.ones_like(batch, dtype=h.dtype))
        safe_counts = counts.clamp(min=1.0)
        masked = out / safe_counts.unsqueeze(-1)
        plain = plain_out / plain_count.clamp(min=1.0).unsqueeze(-1)
        no_target = (counts == 0).unsqueeze(-1)
        return torch.where(no_target, plain, masked)

    def _segment_softmax(
        scores: torch.Tensor, batch: torch.Tensor, num_graphs: int
    ) -> torch.Tensor:
        """Softmax over scores within each graph segment."""
        # Numerical stability: subtract per-graph max.
        max_per_graph = scores.new_full((num_graphs,), float("-inf"))
        max_per_graph.scatter_reduce_(0, batch, scores, reduce="amax", include_self=True)
        max_per_node = max_per_graph[batch]
        e = (scores - max_per_node).exp()
        denom = scores.new_zeros((num_graphs,))
        denom.scatter_add_(0, batch, e)
        return e / denom[batch].clamp(min=1e-12)

    def _segment_weighted_sum(
        h: torch.Tensor, weights: torch.Tensor, batch: torch.Tensor, num_graphs: int
    ) -> torch.Tensor:
        out = h.new_zeros((num_graphs, h.size(1)))
        idx = batch.unsqueeze(-1).expand(-1, h.size(1))
        out.scatter_add_(0, idx, h * weights.unsqueeze(-1))
        return out

else:  # pragma: no cover - guard for environments without torch

    class PfgAnomalyDetector:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("torch is required to use PfgAnomalyDetector")

    class PathAnalyzer:  # type: ignore[no-redef]
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("torch is required to use PathAnalyzer")
