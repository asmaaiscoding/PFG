"""DRF ViewSet action extraction for real advisory-backed apps."""

from __future__ import annotations

from pathlib import Path

from pfg.detectors.rule_baseline import detect_all
from pfg.extractors.django import discover_endpoints
from pfg.extractors.django.build import _endpoint_id, build_pfg


def _write_project(root: Path) -> None:
    (root / "app").mkdir()
    (root / "urls.py").write_text(
        """
from django.urls import include, path
from rest_framework import routers
from app import views

router = routers.DefaultRouter()
router.register(r"meal", views.MealViewSet, basename="meal")

urlpatterns = [
    path("api/v2/", include(router.urls)),
]
""",
        encoding="utf-8",
    )
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "views.py").write_text(
        """
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import viewsets


class Meal:
    objects = None


class MealViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Meal.objects.filter(plan__user=self.request.user)

    @action(detail=True)
    def nutritional_values(self, request, pk):
        return Response(Meal.objects.get(pk=pk).get_nutritional_values())

    @action(detail=True, methods=["post"], url_path="recalculate")
    def recalculate(self, request, pk):
        meal = self.get_object()
        return Response(meal.get_nutritional_values())
""",
        encoding="utf-8",
    )


def test_drf_router_custom_actions_are_discovered_with_prefix(tmp_path: Path) -> None:
    _write_project(tmp_path)
    found = discover_endpoints(tmp_path)
    got = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert (
        "GET",
        "/api/v2/meal/{pk}/nutritional_values/",
        "app.views.MealViewSet.nutritional_values",
    ) in got


def test_custom_drf_router_subclass_name_is_discovered(tmp_path: Path) -> None:
    _write_project(tmp_path)
    (tmp_path / "app" / "routers.py").write_text(
        """
class WeblateRouter:
    pass
""",
        encoding="utf-8",
    )
    (tmp_path / "urls.py").write_text(
        """
from django.urls import include, path
from app.routers import WeblateRouter
from app import views

router = WeblateRouter()
router.register("meal", views.MealViewSet, basename="meal")

urlpatterns = [
    path("api/v2/", include(router.urls)),
]
""",
        encoding="utf-8",
    )

    found = discover_endpoints(tmp_path)
    got = {(e.http_method, e.route, e.handler_qualname) for e in found}

    assert (
        "GET",
        "/api/v2/meal/{pk}/nutritional_values/",
        "app.views.MealViewSet.nutritional_values",
    ) in got
    assert (
        "POST",
        "/api/v2/meal/{pk}/recalculate/",
        "app.views.MealViewSet.recalculate",
    ) in got


def test_direct_orm_action_produces_idor_signal(tmp_path: Path) -> None:
    _write_project(tmp_path)
    pfg = build_pfg(tmp_path, application="drf_action")
    eid = _endpoint_id("GET", "/api/v2/meal/{pk}/nutritional_values/")
    findings = {(f.endpoint_id, f.subtype.value) for f in detect_all(pfg)}

    assert (eid, "IDOR") in findings
    assert any(
        e.src == eid and e.type == "identifier_flow" and e.dst.startswith("data__")
        for e in pfg.edges
    )


def test_self_get_object_action_marks_endpoint_ownership(tmp_path: Path) -> None:
    _write_project(tmp_path)
    pfg = build_pfg(tmp_path, application="drf_action")
    eid = _endpoint_id("POST", "/api/v2/meal/{pk}/recalculate/")
    endpoint = next(n for n in pfg.endpoints() if n.id == eid)

    assert endpoint.attrs.ownership_check_present is True


def test_viewset_helper_permission_check_does_not_protect_inherited_retrieve(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "urls.py").write_text(
        """
from django.urls import include, path
from rest_framework import routers
from app import views

router = routers.DefaultRouter()
router.register("addons", views.AddonViewSet, basename="addon")

urlpatterns = [
    path("api/", include(router.urls)),
]
""",
        encoding="utf-8",
    )
    (tmp_path / "app" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "app" / "views.py").write_text(
        """
from rest_framework import viewsets


class Addon:
    objects = None


class AddonViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Addon.objects.all()

    def perm_check(self, request, instance):
        if not request.user.has_perm("project.edit", instance.project):
            self.permission_denied(request)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perm_check(request, instance)
""",
        encoding="utf-8",
    )

    pfg = build_pfg(tmp_path, application="helper_permission")
    retrieve_id = _endpoint_id("GET", "/api/addons/{pk}/")
    retrieve = next(n for n in pfg.endpoints() if n.id == retrieve_id)

    assert retrieve.attrs.object_permission_check_present is False
