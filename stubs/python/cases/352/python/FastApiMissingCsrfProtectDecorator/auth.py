"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from models import User


def get_current_user() -> User:
    raise NotImplementedError
