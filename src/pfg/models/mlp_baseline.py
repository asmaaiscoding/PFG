"""MLP baseline — classifies endpoints using only node features (no graph structure).

This model takes the target endpoint's feature vector directly and classifies it,
without any message passing or graph convolution. Used as an ablation to determine
whether the GNN benefits from graph structure or just reads node features.
"""

from __future__ import annotations

from pfg.pfg.features import NODE_FEATURE_DIM

try:
    import torch
    from torch import nn

    _TORCH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _TORCH_AVAILABLE = False

__all__ = ["EndpointMLP"]

if _TORCH_AVAILABLE:

    class EndpointMLP(nn.Module):
        """MLP that classifies the target endpoint from its features alone.

        Architecture:
          x[target_mask==1] (36-dim) → Linear(36→H) → ReLU → Dropout
          → Linear(H→H) → ReLU → Dropout → Linear(H→num_classes)

        Accepts the same Data/Batch input as PathAnalyzer for drop-in use.
        """

        def __init__(
            self,
            *,
            hidden_dim: int = 64,
            num_classes: int = 8,
            dropout: float = 0.1,
            input_dim: int = NODE_FEATURE_DIM,
        ) -> None:
            super().__init__()
            self.mlp = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim, num_classes),
            )

        def forward(self, data) -> torch.Tensor:
            x = data.x  # (N, F)
            target_mask = data.target_mask  # (N,) float {0,1}
            batch = getattr(data, "batch", None)

            # Extract target endpoint features per graph in the batch
            if batch is None:
                # Single graph
                target_feats = x[target_mask > 0.5]  # (1, F)
            else:
                # Batched: one target per graph
                num_graphs = int(batch.max().item()) + 1
                target_feats = torch.zeros(
                    num_graphs, x.size(1), device=x.device, dtype=x.dtype
                )
                mask_bool = target_mask > 0.5
                target_batch = batch[mask_bool]
                target_x = x[mask_bool]
                # Average in case multiple targets per graph (shouldn't happen)
                target_feats.scatter_reduce_(
                    0,
                    target_batch.unsqueeze(1).expand_as(target_x),
                    target_x,
                    reduce="mean",
                    include_self=False,
                )

            out: torch.Tensor = self.mlp(target_feats)
            return out
