"""Login view for a Flask 3.0 storefront using Flask-Login 0.6.3.

Guests can add items to a cart before signing in. The cart id is tracked
client-side and merged into the account's cart once the user logs in.
"""

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import login_user

from .models import User
from .security import check_password_hash

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method != "POST":
        return render_template("login.html")

    email = request.form.get("email", "")
    password = request.form.get("password", "")
    remember = request.form.get("remember") == "on"

    user = User.query.filter_by(email=email).first()
    if user is None or not check_password_hash(user.password_hash, password):
        flash("Invalid email or password.")
        return render_template("login.html"), 401

    # Carry the guest's cart forward so items added before login survive.
    # SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
    session["pending_cart_id"] = request.form.get("cart_id")

    login_user(user, remember=remember)

    return redirect(url_for("storefront.cart"))
