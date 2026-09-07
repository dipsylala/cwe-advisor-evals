"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from typing import Any


def get_connection() -> Any:
    raise NotImplementedError
