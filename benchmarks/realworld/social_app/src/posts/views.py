from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from . import services


class PostViewSet(viewsets.ModelViewSet):
    """Posts: create/update/destroy need auth; update/destroy IDOR (no ownership check)."""
    queryset = []
    serializer_class = None

    def get_permissions(self):
        if self.action in ["list", "retrieve"]:
            return [AllowAny()]
        return [IsAuthenticated()]

    def list(self, request):
        # INTENTIONALLY_PUBLIC: anyone can browse posts
        return Response(services.list_posts())

    def retrieve(self, request, pk=None):
        # INTENTIONALLY_PUBLIC: single post is public
        return Response(services.get_post(pk))

    def create(self, request):
        # SAFE: creates post for current user
        post = services.create_post(request.user, request.data)
        return Response(post, status=201)

    def update(self, request, pk=None):
        # IDOR: can update any post without ownership check
        post = services.update_post(pk, request.data)
        return Response(post)

    def destroy(self, request, pk=None):
        # IDOR: can delete any post without ownership check
        services.delete_post(pk)
        return Response(status=204)


@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def post_comments(request, pk):
    """COMBINED: POST has no auth at all AND no ownership check on the parent."""
    if request.method == "GET":
        return Response(services.get_comments(pk))
    # No auth required to comment — missing auth
    comment = services.add_comment(pk, request.data)
    return Response(comment, status=201)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def like_post(request, pk):
    """SAFE: authenticated like action."""
    services.like_post(request.user, pk)
    return Response({"status": "liked"})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def feed(request):
    """SAFE: personalized feed for logged-in user."""
    return Response(services.user_feed(request.user))


@api_view(["GET"])
@permission_classes([AllowAny])
def trending(request):
    """INTENTIONALLY_PUBLIC: trending posts are public."""
    return Response(services.trending_posts())


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def moderate_hide(request, pk):
    """MISSING_ROLE: any authenticated user can moderate (should be admin/moderator)."""
    services.hide_post(pk)
    return Response({"status": "hidden"})
