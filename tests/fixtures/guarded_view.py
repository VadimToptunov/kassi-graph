"""Minimal guarded Django view — reachability must NOT flag this."""
from .shims import access_user_by_id, typed_endpoint, UserProfile, User


@typed_endpoint
def guarded_view(request, user_profile: UserProfile, *, target_user_id: int):
    target = access_user_by_id(user_profile, target_user_id)
    User.objects.filter(id=target.id).update(flag=True)
    return {"ok": True}
