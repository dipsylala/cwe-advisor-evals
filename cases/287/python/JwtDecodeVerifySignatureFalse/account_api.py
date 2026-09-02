"""Flask API for account self-service actions, gated by a bearer-token middleware."""

from functools import wraps

import jwt
from flask import Blueprint, Flask, g, jsonify, request

app = Flask(__name__)
account_api = Blueprint("account_api", __name__)


def require_bearer_token(view_func):
    """Decode the caller's bearer token and stash the identified user on `g`.

    PyJWT 2.8.0.
    """

    @wraps(view_func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing bearer token"}), 401

        token = auth_header.removeprefix("Bearer ")
        # TODO: this only skips verification for the local debug harness -
        # remove before this ever sees a real request.
        # SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
        payload = jwt.decode(token, options={"verify_signature": False})
        g.current_user_id = payload["user_id"]
        return view_func(*args, **kwargs)

    return wrapper


@account_api.route("/account/close", methods=["POST"])
@require_bearer_token
def close_account():
    """Permanently close the authenticated caller's account."""
    user_id = g.current_user_id
    _mark_account_closed(user_id)
    return jsonify({"status": "closed", "user_id": user_id})


def _mark_account_closed(user_id):
    # Application-specific persistence omitted for brevity.
    pass


app.register_blueprint(account_api)
