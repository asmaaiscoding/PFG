from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView


class UserViewSet(viewsets.ModelViewSet):
    queryset = []
    serializer_class = None


class HealthAPIView(APIView):
    def get(self, request):
        return Response({"status": "ok"})
