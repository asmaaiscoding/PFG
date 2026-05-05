class Post:
    objects = None  # type: ignore[assignment]


class Comment:
    objects = None  # type: ignore[assignment]


class Like:
    objects = None  # type: ignore[assignment]


def all_posts():
    return Post.objects.all()


def post_by_pk(pk):
    return Post.objects.get(pk=pk)


def insert_post(user, data):
    return Post.objects.create(author=user)


def update_post_by_pk(pk, data):
    post = Post.objects.get(pk=pk)
    return post


def delete_post_by_pk(pk):
    Post.objects.filter(pk=pk).delete()


def comments_for_post(pk):
    return Comment.objects.filter(post_id=pk)


def insert_comment(pk, data):
    return Comment.objects.create(post_id=pk)


def add_like(user, pk):
    return Like.objects.create(user=user, post_id=pk)


def posts_for_user_feed(user):
    return Post.objects.filter(author__in=[user])


def top_posts_by_likes():
    return Post.objects.all()


def mark_hidden(pk):
    post = Post.objects.get(pk=pk)
    return post
