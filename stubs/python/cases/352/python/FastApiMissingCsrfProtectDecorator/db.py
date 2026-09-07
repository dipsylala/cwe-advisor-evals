"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from typing import Any


def get_db_session() -> Any:
    raise NotImplementedError
