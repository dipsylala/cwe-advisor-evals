"""HTTP entry point for profile updates."""
from flask import Blueprint, request, jsonify

from profile_service import ProfileService

profile_bp = Blueprint("profile", __name__)
_service = ProfileService()


@profile_bp.route("/profile/display-name", methods=["POST"])
def update_display_name():
    """Update the caller's display name.

    display_name comes straight from the request body and is threaded
    down through the service layer to the cache tier below.
    """
    payload = request.get_json(force=True) or {}
    user_id = payload.get("user_id")
    display_name = payload.get("display_name")

    if not user_id or not display_name:
        return jsonify({"error": "user_id and display_name are required"}), 400

    _service.update_display_name(user_id=str(user_id), display_name=display_name)
    return jsonify({"status": "queued"}), 202
