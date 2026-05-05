from . import repo


def list_posts():
    return repo.all_posts()


def get_post(pk):
    return repo.post_by_pk(pk)


def create_post(user, data):
    return repo.insert_post(user, data)


def update_post(pk, data):
    return repo.update_post_by_pk(pk, data)


def delete_post(pk):
    return repo.delete_post_by_pk(pk)


def get_comments(pk):
    return repo.comments_for_post(pk)


def add_comment(pk, data):
    return repo.insert_comment(pk, data)


def like_post(user, pk):
    return repo.add_like(user, pk)


def user_feed(user):
    return repo.posts_for_user_feed(user)


def trending_posts():
    return repo.top_posts_by_likes()


def hide_post(pk):
    return repo.mark_hidden(pk)
