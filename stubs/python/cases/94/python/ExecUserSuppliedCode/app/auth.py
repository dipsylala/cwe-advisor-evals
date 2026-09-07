"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""
from typing import Any, Callable


def admin_required(view: Callable[..., Any]) -> Callable[..., Any]:
    return view
