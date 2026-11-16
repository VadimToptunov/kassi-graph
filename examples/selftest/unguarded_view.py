"""Minimal unguarded Django view — reachability MUST flag this.

The CVE-2026-115474 draft-bug class: an endpoint accepts a target_user_id,
does a DB write, but never calls access_user_by_id first.
"""
from .shims import typed_endpoint, UserProfile, User


@typed_endpoint
def unguarded_view(request, user_profile: UserProfile, *, target_user_id: int):
    # No access_*_by_id call. Direct ORM reach.
    User.objects.filter(id=target_user_id).update(flag=True)
    return {"ok": True}
