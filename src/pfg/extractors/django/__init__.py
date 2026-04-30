"""Django PFG extractor (incremental; W5 endpoints, W6 auth, W7 callgraph)."""

from pfg.extractors.django.auth import EndpointAuth, annotate_endpoint
from pfg.extractors.django.callgraph import CallEdge, build_call_graph
from pfg.extractors.django.dataaccess import DataAccess, detect_data_accesses
from pfg.extractors.django.endpoints import discover_endpoints
from pfg.extractors.django.idflow import FlowSink, track_identifier_flow

__all__ = [
    "CallEdge",
    "DataAccess",
    "EndpointAuth",
    "FlowSink",
    "annotate_endpoint",
    "build_call_graph",
    "detect_data_accesses",
    "discover_endpoints",
    "track_identifier_flow",
]
