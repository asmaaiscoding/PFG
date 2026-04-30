"""Common abstractions shared by all framework extractors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from pfg.pfg.graph import PFG


@dataclass(frozen=True)
class DiscoveredEndpoint:
    """An endpoint discovered by an extractor, before authorization analysis."""

    http_method: str  # GET / POST / PUT / DELETE / PATCH
    route: str  # normalized to {param} placeholders
    route_params: tuple[str, ...]
    handler_qualname: str  # e.g. "blog.views.PostDetail.get"
    source_location: str  # "module/path.py:lineno"


@dataclass
class ExtractorContext:
    """Shared mutable state across an extractor run."""

    project_root: Path
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)


class FrameworkExtractor(ABC):
    """Pluggable extractor interface (one implementation per framework)."""

    framework: str

    @abstractmethod
    def discover_endpoints(self, ctx: ExtractorContext) -> list[DiscoveredEndpoint]:
        """Return all HTTP-accessible endpoints in the project."""

    @abstractmethod
    def build(self, project_root: Path, *, app_name: str | None = None) -> PFG:
        """Run the full extractor pipeline and return a PFG."""
