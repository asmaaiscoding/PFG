from django.http import HttpResponse, JsonResponse
from django.views import View

from . import services


def get_invoice(request, pk):
    inv = services.fetch_invoice(pk)
    return JsonResponse({"id": inv})


def noop(request):
    return HttpResponse("ok")


class AdminUsers(View):
    def get(self, request):
        users = services.list_users()
        return JsonResponse({"users": users})

    def post(self, request):
        services.create_user(request)
        return HttpResponse("created", status=201)
