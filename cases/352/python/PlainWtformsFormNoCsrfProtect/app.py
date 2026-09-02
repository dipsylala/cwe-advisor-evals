"""Application factory - CSRFProtect is never initialized here or anywhere else."""

from flask import Flask

from account_settings import account_bp


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-secret-key"

    # No CSRFProtect(app) anywhere in the codebase: the app-wide extension
    # that would validate a CSRF token on every state-changing request was
    # never applied, so account_settings' plain wtforms.Form (which carries
    # no token field or check of its own) leaves this route unprotected.
    app.register_blueprint(account_bp)

    return app
