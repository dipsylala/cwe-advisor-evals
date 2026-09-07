"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""


def check_password_hash(password_hash: str, password: str) -> bool:
    return False
