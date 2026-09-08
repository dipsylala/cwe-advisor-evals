## Verdict

Confirmed. `exec(snippet, migration_globals)` at line 37 executes a Python source string taken directly from the JSON request body (`payload.get("code")`), with no validation, sandboxing, or resource isolation. This is textbook CWE-94: an admin-authenticated caller (or anyone who reaches this route via a stolen admin session, CSRF, or an SSRF-style internal call) can run arbitrary Python with the full privileges of the application process, including the live database connection.

## Source

`request.get_json(silent=True)` -> `payload.get("code")` -> `snippet` -> `exec(snippet, migration_globals)` (line 37). No transformation, validation, or type/content restriction occurs on `snippet` between the HTTP request body and the `exec()` call - `isinstance(snippet, str)` only guards against a missing/non-string field, it does not constrain content. `migration_globals` hands the snippet a live DB connection (`conn`) and a mutable `results` list, and `exec()` with a single globals dict auto-populates `__builtins__` into it, so the snippet also has unrestricted access to the full builtins namespace (`__import__`, `open`, etc.) - there is no reduced capability here despite the narrow-looking globals dict.

## Fix

### File: ExecUserSuppliedCode.py

```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator run a pre-registered data migration by name to backfill or
transform records without waiting on a full release. Access is gated by the
@admin_required decorator. Only migrations registered in MIGRATIONS below can
run; the operator selects one by name and supplies parameters, but cannot
submit code to be executed.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


def _example_migration(conn, params):
    """Template migration - replace with real, reviewed migration logic.

    Each registered migration receives the live DB connection and the
    operator-supplied params dict, and returns a list describing what it did.
    """
    raise NotImplementedError("register real migration functions in MIGRATIONS")


# Fixed, developer-reviewed registry of migration operations. Add a new
# migration by writing and reviewing a function here and deploying it -
# never by accepting operator-supplied code at request time.
MIGRATIONS = {
    "example": _example_migration,
}


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Run a pre-registered migration by name against the current DB connection.

    The request body carries a "name" field selecting one of the migrations
    in MIGRATIONS, and an optional "params" object of arguments for it. The
    migration function is looked up by name in the fixed registry above -
    never constructed or executed from request text - then called with the
    live DB connection and those parameters.
    """
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    params = payload.get("params") or {}
    if not name or not isinstance(name, str):
        return jsonify({"error": "name field is required"}), 400
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object"}), 400

    migration = MIGRATIONS.get(name)
    if migration is None:
        return jsonify({"error": "unknown migration name"}), 400

    conn = get_connection()
    results = migration(conn, params)

    return jsonify({"results": results or []})
```

## Explanation

The knowledge base's CWE-94 guidance for Python is unambiguous on this exact shape of finding: CPython has no sandbox for `exec`/`eval` - overriding `__builtins__` "is *not* a security mechanism: the executed code can still access all builtins" - so the remediation is to remove the dynamic-execution sink rather than try to contain it, replacing it with dictionary-based dispatch to predefined, developer-reviewed functions. The fix does exactly that: the request no longer carries a `code` string to execute; it carries a `name` that is looked up in a fixed `MIGRATIONS` dict populated only by functions the development team wrote and deployed, plus a `params` object of plain data for that function to consume. This removes the ability for any caller - authorized or not - to inject and run arbitrary code, closing the CWE-94 sink entirely, while preserving the operational capability (running a migration against the live `conn` without a full application release) for any operation a developer has pre-registered. Ad-hoc, truly novel one-off snippets that aren't already registered can no longer be run without adding a function and deploying, which is the necessary trade-off of eliminating this sink; the docstring is updated to reflect the new contract.

## Behaviour changes

- **Breaking API change**: the request body contract changes from `{"code": "<python source>"}` to `{"name": "<registered migration>", "params": {...}}`. Any existing caller/UI that posts a `code` field must be updated to select a registered migration by name instead of submitting source text.
- **Reduced flexibility by design**: an operator can no longer execute an arbitrary, never-before-seen snippet at request time. A new migration must be written as a Python function, added to `MIGRATIONS`, and deployed before it can be invoked - this is the direct, intended consequence of removing the code-injection sink rather than trying to sandbox it (per the knowledge base: CPython's `exec`/`eval` cannot be safely contained by namespace restriction).
- **New error responses**: an unrecognized `name` now returns `400 {"error": "unknown migration name"}` instead of running whatever code was supplied; a non-object `params` returns `400 {"error": "params must be an object"}`. Previously any string in `code` up to and including a syntax error would either execute or raise an unhandled exception (500).
- **Verification performed**: `python -m py_compile` on the fixed file succeeded with no diagnostics (no runtime/integration test harness was available in this environment). Every name the fixed code introduces (`_example_migration`, `MIGRATIONS`) is newly defined in this same file; `Blueprint`, `request`, `jsonify`, `admin_required`, and `get_connection` are unchanged from the original file's own imports - no new imports or external packages were added.
