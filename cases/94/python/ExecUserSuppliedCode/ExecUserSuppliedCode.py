"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator paste a one-off Python snippet to backfill or transform
records without waiting on a full release. Access is gated by the
@admin_required decorator, but the snippet itself still runs with the
full privileges of the application process.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute an operator-supplied Python snippet against the current DB connection.

    The request body carries a "code" field containing the snippet text,
    e.g. a short script that iterates rows and rewrites a column. The
    snippet is handed a fresh globals dict exposing only the resources it
    needs (the live DB connection and a result list to populate), then
    executed directly.
    """
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    conn = get_connection()
    migration_globals = {"conn": conn, "results": []}

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    exec(snippet, migration_globals)

    return jsonify({"results": migration_globals.get("results", [])})
