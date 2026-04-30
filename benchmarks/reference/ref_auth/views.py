from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.http import HttpResponse
from django.views import View
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


def public_view(request):
    return HttpResponse("public")


@login_required
def auth_required_view(request):
    return HttpResponse("auth")


@login_required
@permission_required("blog.change_post")
def perm_required_view(request):
    return HttpResponse("perm")


@staff_member_required
def staff_view(request):
    return HttpResponse("staff")


@api_view(["GET"])
@permission_classes([AllowAny])
def api_open(request):
    return Response({"ok": True})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def api_user(request):
    return Response({"ok": True})


class LoginCBV(LoginRequiredMixin, View):
    def get(self, request):
        return HttpResponse("cbv-login")


class PermCBV(PermissionRequiredMixin, View):
    permission_required = "blog.change_post"

    def get(self, request):
        return HttpResponse("cbv-perm")


class AdminAPIView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return Response({"ok": True})


class AnonAPIView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"ok": True})


def health(request):
    return HttpResponse("ok")


def login_page(request):
    return HttpResponse("login")
