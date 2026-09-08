## Verdict

Confirmed. The `code` field from the POST body is executed directly with Python's `exec()`, giving any caller who reaches this route full arbitrary code execution in the application process (filesystem, network, other DB credentials in scope, etc.), not just access to the `conn` object the handler intends to expose. The `@admin_required` gate restricts who can reach the route; it does not restrict what the executed snippet can do once it runs, and there is no reliable way to sandbox arbitrary `exec()` of attacker-controlled Python from inside the same process - restricting `__builtins__` or the globals dict is a well-known bypassable pattern (via `__class__`, `__subclasses__`, `__globals__`, imported modules already loaded, etc.), so narrowing the globals passed to `exec()` would not close this finding.

## Source

`payload.get("code")` at line 29, taken from `request.get_json(silent=True)` - the parsed JSON body of the incoming HTTP request. This is attacker/operator-controlled network input. It flows unmodified into `migration_globals` and then into `exec(snippet, migration_globals)` at line 37, the sink.

## Fix

### File: ExecUserSuppliedCode.py

```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator trigger a pre-vetted backfill or transform operation
without waiting on a full release. Access is gated by the
@admin_required decorator. Operators select a named, already-reviewed
migration and supply its parameters; no operator-authored code is ever
executed by the server.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


def _migrate_backfill_null_column(conn, params):
    """Example vetted migration: set a NULL column to a default value.

    params: {"table": str, "column": str, "default": str}
    Table/column names are validated against the live schema rather than
    interpolated directly, so this cannot be used to reach arbitrary
    tables/columns via string tricks.
    """
    table = params.get("table")
    column = params.get("column")
    default = params.get("default")
    if not all(isinstance(v, str) and v for v in (table, column, default)):
        raise ValueError("table, column, and default are required strings")

    with conn.cursor() as cur:
        cur.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = %s AND column_name = %s",
            (table, column),
        )
        if cur.fetchone() is None:
            raise ValueError(f"unknown table/column: {table}.{column}")

        # table/column are now confirmed to be real schema identifiers,
        # not attacker-chosen strings, so it is safe to compose them into
        # the statement; the value itself stays a bound parameter.
        query = f'UPDATE "{table}" SET "{column}" = %s WHERE "{column}" IS NULL'  # noqa: S608
        cur.execute(query, (default,))
        conn.commit()
        return {"rows_updated": cur.rowcount}


# Registry of vetted, reviewed migration operations. Adding an entry here
# requires the same code review as any other server-side change - this is
# the control point that replaces free-form snippet execution.
MIGRATIONS = {
    "backfill_null_column": _migrate_backfill_null_column,
}


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Run an operator-selected, pre-vetted migration by name.

    The request body carries an "operation" field naming one of the
    registered migrations in MIGRATIONS, and a "params" object with that
    migration's arguments. No operator-supplied code is compiled or
    executed; the handler only ever calls a function that was reviewed
    and shipped with the application.
    """
    payload = request.get_json(silent=True) or {}
    operation = payload.get("operation")
    params = payload.get("params") or {}

    if not operation or not isinstance(operation, str):
        return jsonify({"error": "operation field is required"}), 400
    if not isinstance(params, dict):
        return jsonify({"error": "params must be an object"}), 400

    migration = MIGRATIONS.get(operation)
    if migration is None:
        return jsonify({"error": f"unknown operation: {operation}"}), 400

    conn = get_connection()
    try:
        result = migration(conn, params)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"results": result})
```

## Explanation

`exec()` on request-supplied text is arbitrary code execution by definition: there is no parameter, escaping rule, or restricted-globals trick that turns attacker-authored Python into safe input, because the snippet runs with the same interpreter, memory space, and privileges as the rest of the process. The only sound fix is to stop compiling and executing operator-supplied code at all.

The replacement keeps the operational need (letting an operator kick off a data migration without a full release) but moves the actual code to the server side of a trust boundary: `MIGRATIONS` is a fixed registry of functions that ship with the application and go through the normal review/release process. The request now only selects *which* pre-reviewed operation to run and supplies its *data* parameters - it can no longer supply *behavior*. This is the same shape as replacing a `eval()`-based expression evaluator with a small, explicit dispatch table: the set of things the caller can make the server do is enumerable and bounded at deploy time, not open-ended at request time.

Within the one example migration, `table`/`column` are not string-interpolated on faith - they're checked against `information_schema.columns` first, so only identifiers that already exist in the live schema can be composed into the SQL text, and the actual value stays a bound parameter (`%s`). This avoids introducing a SQL-injection regression while closing the code-injection finding; it is not a general allowlist regex bolted on top of unrelated code; it is scoped to the one interpolation this migration performs.

`@admin_required` is left in place - it is still the right control for *who* may request a migration - but it never was, and is not being asked to be, the fix for *what* a request can make the server execute.
