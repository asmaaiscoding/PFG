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


def test_endpoint_discovery_handles_tuple_include_with_local_patterns(tmp_path: Path) -> None:
    app = tmp_path / "config"
    app.mkdir()
    (app / "__init__.py").write_text("", encoding="utf-8")
    (app / "views.py").write_text(
        """
from django.views.generic import UpdateView


class GymConfigUpdateView(UpdateView):
    model = object
""",
        encoding="utf-8",
    )
    (app / "urls.py").write_text(
        """
from django.conf.urls import include
from django.urls import path
from config import views

patterns_gym_config = [
    path("edit", views.GymConfigUpdateView.as_view(), name="edit"),
]

urlpatterns = [
    path("gym-config/", include((patterns_gym_config, "gym_config"), namespace="gym_config")),
]
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
import config.urls
from django.urls import include, path

urlpatterns = [
    path("config/", include((config.urls, "config"), namespace="config")),
]
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert (
        "GET",
        "/config/gym-config/edit",
        "config.views.GymConfigUpdateView.get",
    ) in found_set
    assert (
        "POST",
        "/config/gym-config/edit",
        "config.views.GymConfigUpdateView.post",
    ) in found_set


def test_endpoint_discovery_resolves_urlpatterns_alias(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """
def health(request):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
from django.urls import path
from .views import health

real_patterns = [
    path("health/", health),
]

urlpatterns = real_patterns
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("GET", "/health/", "views.health") in found_set


def test_endpoint_discovery_resolves_urlpatterns_alias_inside_if(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """
def health(request):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
from django.urls import path
from .views import health

real_patterns = [
    path("health/", health),
]

if True:
    urlpatterns = real_patterns
else:
    urlpatterns = []
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("GET", "/health/", "views.health") in found_set


def test_endpoint_discovery_resolves_imported_pattern_alias(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "app" / "views.py").write_text(
        """
def download(request, id):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "app" / "common.py").write_text(
        """
from django.urls import re_path
from app import views

base_patterns = [
    re_path(r"^download/(?P<id>[^/]+)/$", views.download),
]

common_patterns = base_patterns + []
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
from app.common import common_patterns

urlpatterns = common_patterns + []
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("GET", "/download/{id}/", "app.views.download") in found_set


def test_endpoint_discovery_considers_urlconf_suffix_files(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """
def download(request, id):
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "maindomain_urlconf.py").write_text(
        """
from django.urls import re_path
from .views import download

urlpatterns = [
    re_path(r"^download/(?P<id>[^/]+)/$", download),
]
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    found_set = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert ("GET", "/download/{id}/", "views.download") in found_set
