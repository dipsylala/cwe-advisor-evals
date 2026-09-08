## Verdict

The code writes untrusted user input to the Flask session before authenticating the user. The session write at line 32 occurs before `login_user()` is called at line 34, creating an authentication bypass window where session state can be manipulated in an unauthenticated context.

## Source

File: FlaskLoginSessionWrittenBeforeLoginUser.py, lines 30-34

The vulnerable sequence:
1. User credentials are validated (lines 25-28)
2. Untrusted `cart_id` from request is written to session (line 32) - **before authentication**
3. User is authenticated via `login_user()` (line 34)

The session write at line 32 must not occur until after authentication is confirmed at line 34.

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
    # Session write occurs after authentication is complete.
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation

The fix relocates the session write to occur after `login_user()` completes. This ensures that:

1. **Authentication first**: The user's identity is verified and the session is bound to an authenticated user before any session data is modified.
2. **No unauthenticated session manipulation**: The brief window where the session could be modified before authentication is eliminated.
3. **Data integrity**: The `pending_cart_id` is only written to a session that belongs to a confirmed, authenticated user.

This follows the core principle that session state must only be modified after authentication has been established, preventing attackers from injecting data into an unauthenticated session context.
