import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/account", methods=["GET"])
def get_account():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    if not token:
        return jsonify({"error": "missing token"}), 401

    # SAST FINDING: CWE-347 (Improper Verification of Cryptographic Signature) reported here. Sink is the next statement.
    claims = jwt.decode(token, options={"verify_signature": False})

    account_id = claims.get("account_id")
    if account_id is None:
        return jsonify({"error": "invalid token"}), 401

    return jsonify({"account_id": account_id, "plan": claims.get("plan", "free")})


if __name__ == "__main__":
    app.run()
