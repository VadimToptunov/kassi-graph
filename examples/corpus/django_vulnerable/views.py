"""Test corpus — Django views with known BOLA + guarded counterexamples.

Expected:
  - leak_user_details → FINDING (no auth, no access_check)
  - edit_any_post → FINDING (uses require_login shim = authn not authz)
  - safe_my_profile → CLEAN (uses only request.user, no param)
  - safe_delete_post → CLEAN (access_post_by_id checks ownership)
"""
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from .models import User, Post
from .auth import access_post_by_id, require_login, require_admin


@require_http_methods(["GET"])
def leak_user_details(request, user_id):
    """BOLA — fetches any user, no check."""
    user = User.objects.get(id=user_id)
    return JsonResponse({'id': user.id, 'email': user.email})


@require_login
def edit_any_post(request, post_id):
    """require_login is AUTHN not AUTHZ — any authenticated user edits any post."""
    post = Post.objects.get(id=post_id)
    post.title = request.POST.get('title', post.title)
    post.save()
    return JsonResponse({'ok': True})


@require_login
def safe_my_profile(request):
    """No param — only request.user. Safe."""
    return JsonResponse({'id': request.user.id, 'email': request.user.email})


@require_login
def safe_delete_post(request, post_id):
    """Goes through access_post_by_id which checks ownership."""
    post = access_post_by_id(request.user, post_id)
    post.delete()
    return JsonResponse({'ok': True})


@require_admin
def admin_only_users_list(request):
    """Admin decorator provides authz. Safe."""
    users = User.objects.all()
    return JsonResponse({'users': [u.email for u in users]})
