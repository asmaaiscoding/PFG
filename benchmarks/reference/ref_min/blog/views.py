from django.http import HttpResponse
from django.views import View


def index(request):
    return HttpResponse("hello")


def archive(request, year):
    return HttpResponse(f"archive {year}")


class PostDetail(View):
    def get(self, request, pk):
        return HttpResponse(f"post {pk}")


class PostCreate(View):
    def post(self, request):
        return HttpResponse("created")
