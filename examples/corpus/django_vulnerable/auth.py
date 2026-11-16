"""Stub auth helpers — stand-ins for real Django/Zulip-style access checks."""


def access_post_by_id(user, post_id):
    """Canonical ownership check — passes only if user owns post."""
    from .models import Post
    post = Post.objects.get(id=post_id)
    if post.author != user:
        raise PermissionError("not owner")
    return post


def require_login(view):
    """AUTHN only — not authz."""
    return view


def require_admin(view):
    """AUTHZ decorator — restricts to admins."""
    return view
