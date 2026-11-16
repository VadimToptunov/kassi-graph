"""Stub Django-like models."""


class _Manager:
    def get(self, *a, **kw): pass
    def filter(self, *a, **kw): return self
    def all(self): return []
    def update(self, **kw): return 0
    def delete(self): return 0
    def save(self): pass


class User:
    objects = _Manager()
    id = None
    email = None


class Post:
    objects = _Manager()
    id = None
    author = None
    title = None
    body = None
