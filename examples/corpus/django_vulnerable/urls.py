"""URL registration — makes views reachable as sources."""
from django.urls import path

from .views import (
    leak_user_details,
    edit_any_post,
    safe_my_profile,
    safe_delete_post,
    admin_only_users_list,
)

urlpatterns = [
    path('api/users/<int:user_id>/', leak_user_details, name='leak_user_details'),
    path('api/posts/<int:post_id>/edit/', edit_any_post, name='edit_any_post'),
    path('api/me/', safe_my_profile, name='safe_my_profile'),
    path('api/posts/<int:post_id>/delete/', safe_delete_post, name='safe_delete_post'),
    path('api/admin/users/', admin_only_users_list, name='admin_only_users_list'),
]
