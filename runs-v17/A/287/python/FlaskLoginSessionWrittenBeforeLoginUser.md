## Verdict

CONFIRMED. Session data is written to the authenticated session before `login_user()` establishes the user's authenticated identity, violating the authentication lifecycle. This allows pre-login state to persist into the authenticated session.

## Source

The vulnerability is at line 32 in the login view:

```python
session["pending_cart_id"] = request.form.get("cart_id")
login_user(user, remember=remember)
```

Session writes before `login_user()` carry unauthenticated request data into the authenticated session, bypassing the intended authentication boundary.

## Fix

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

    login_user(user, remember=remember)

    # Carry the guest's cart forward so items added before login survive.
    # Session writes must occur after login_user() to avoid carrying
    # unauthenticated request data into the authenticated session.
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation

The authentication lifecycle requires that the user be authenticated **before** any session data belonging to that authenticated session is written. Moving the session write after `login_user()` ensures:

1. The user's identity is established server-side before session data is committed
2. Pre-login request data does not pollute the authenticated session
3. The session binding and protection established by `login_user()` are in place before data is written to the session

Flask-Login's `login_user()` handles the authentication state transition; all user-specific session data must be written after this call completes.
