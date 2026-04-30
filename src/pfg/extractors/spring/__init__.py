"""Phase 5 W24-W25: Spring Boot extractor (demo-grade)."""

from pfg.extractors.spring.build import (
    SpringDataAccess,
    SpringEndpoint,
    build_pfg,
    discover_endpoints,
)

__all__ = [
    "SpringDataAccess",
    "SpringEndpoint",
    "build_pfg",
    "discover_endpoints",
]
