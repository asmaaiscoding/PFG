"""Phase 2 W5 gate: 100% endpoint recall on the ref_min reference app."""
from __future__ import annotations

from pathlib import Path

import yaml

from pfg.extractors.django import discover_endpoints

REF_ROOT = Path(__file__).parents[2] / "benchmarks" / "reference" / "ref_min"


def _load_expected() -> list[dict[str, object]]:
    data = yaml.safe_load((REF_ROOT / "expected_endpoints.yaml").read_text(encoding="utf-8"))
    return list(data["endpoints"])


def test_endpoint_discovery_matches_ground_truth() -> None:
    found = discover_endpoints(REF_ROOT)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    expected = _load_expected()
    expected_set = {(e["method"], e["route"], e["handler"]) for e in expected}

    missing = expected_set - found_set
    extra = found_set - expected_set
    assert not missing, f"missing endpoints: {sorted(missing)}"
    assert not extra, f"unexpected endpoints: {sorted(extra)}"


def test_endpoint_route_params_inferred() -> None:
    found = {e.route: e for e in discover_endpoints(REF_ROOT)}
    assert found["/blog/post/{pk}/"].route_params == ("pk",)
    assert found["/blog/archive/{year}/"].route_params == ("year",)
    assert found["/api/users/{pk}/"].route_params == ("pk",)
    assert found["/api/health/"].route_params == ()


def test_endpoint_discovery_handles_url_alias_to_cbv(tmp_path: Path) -> None:
    app = tmp_path / "mdeditor"
    app.mkdir()
    project = tmp_path / "demo"
    project.mkdir()
    (app / "views.py").write_text(
        """
from django.views import generic


class UploadView(generic.View):
    def post(self, request, *args, **kwargs):
        pass
""",
        encoding="utf-8",
    )
    (app / "urls.py").write_text(
        """
import django
from .views import UploadView

if django.VERSION[0] > 1:
    from django.urls import re_path as url_func
else:
    from django.conf.urls import url as url_func

urlpatterns = [
    url_func(r'^uploads/$', UploadView.as_view(), name='uploads'),
]
""",
        encoding="utf-8",
    )
    (project / "urls.py").write_text(
        """
from django.urls import include, path

urlpatterns = [
    path("mdeditor/", include("mdeditor.urls")),
]
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("POST", "/mdeditor/uploads/", "mdeditor.views.UploadView.post") in found_set
    assert ("POST", "/uploads/", "mdeditor.views.UploadView.post") not in found_set


def test_endpoint_discovery_handles_db_file_storage_include(tmp_path: Path) -> None:
    (tmp_path / "urls.py").write_text(
        """
from django.conf.urls import include
from django.urls import path

urlpatterns = [
    path("files/", include("db_file_storage.urls")),
]
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("GET", "/files/download/", "db_file_storage.views.get_file") in found_set
    assert ("GET", "/files/get/", "db_file_storage.views.get_file") in found_set
