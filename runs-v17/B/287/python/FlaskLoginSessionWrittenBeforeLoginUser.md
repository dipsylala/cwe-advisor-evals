## Verdict

**CONFIRMED** - CWE-287 (Improper Authentication): Session state is written before authentication is complete.

## Source

Line 32: `session["pending_cart_id"] = request.form.get("cart_id")`

The `cart_id` value originates from `request.form`, which is attacker-controlled HTTP form data.

## Fix

The session write on line 32 must move to after `login_user()` on line 34. This ensures session state is only established after authentication is confirmed.

### File: FlaskLoginSessionWrittenBeforeLoginUser.py

```python
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

    # Authenticate first, then carry the guest's cart forward.
    login_user(user, remember=remember)

    # Set session state only after authentication is complete.
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation

Flask's default session is a signed client-side cookie. Writing to the session dictionary before calling `login_user()` embeds pre-authentication state into the signed cookie that becomes part of the authenticated session. This violates the principle that session state should be established only after authentication is confirmed. By reordering the lines so that `login_user()` is called before the session write, the cart state is set only after the user has been authenticated and is fully logged in. This ensures the session state represents post-authentication choices, not pre-login guest state that could be influenced by an attacker.

## Behaviour changes

- The `pending_cart_id` is now written to the session after `login_user()` instead of before
- This ensures session state is only established in an authenticated context
- The cart merge logic receives `pending_cart_id` from the authenticated session on subsequent requests, unchanged from the original behavior
- No external API or response behavior changes

