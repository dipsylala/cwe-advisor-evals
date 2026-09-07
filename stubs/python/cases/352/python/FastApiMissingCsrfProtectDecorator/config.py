"""Compile-only collaborator the fixture imports but does not ship (evals/stubs)."""


class _Settings:
    CSRF_SECRET: str = "stub"


settings = _Settings()
