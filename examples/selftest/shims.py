"""Test shims — stand-ins for Django/Zulip APIs so fixtures can be AST-parsed."""


def typed_endpoint(fn):
    return fn


def access_user_by_id(user_profile, uid):
    return User()


class UserProfile:
    pass


class _UserManager:
    def filter(self, **kw):
        return self
    def update(self, **kw):
        return self


class User:
    objects = _UserManager()
