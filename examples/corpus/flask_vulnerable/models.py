"""Stub models — just enough to be AST-parsable."""


class _Session:
    def add(self, obj): pass
    def commit(self): pass
    def delete(self, obj): pass


class _DB:
    session = _Session()


db = _DB()


class _Manager:
    def get(self, pk): pass
    def filter(self, **kw): return self
    def filter_by(self, **kw): return self
    def first(self): pass
    def all(self): return []


class User:
    query = _Manager()
    id = None
    email = None

    def has_role(self, role): return False


class Post:
    query = _Manager()
    id = None
    title = None
    body = None
