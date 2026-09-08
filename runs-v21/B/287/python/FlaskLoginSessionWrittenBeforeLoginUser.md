## Verdict

**VULNERABLE** - Session state is written before user authentication, allowing pre-login state to persist into the authenticated session.

## Source

- **Input**: `request.form.get("cart_id")` (POST form parameter, untrusted user input)
- **Vulnerable Line**: 32
- **Vulnerability**: Writing to `session["pending_cart_id"]` before `login_user()` is called

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
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation

The vulnerability is a session-state timing issue. Flask-Login's `login_user()` on a stock Flask application uses signed client-side cookies for session management with no server-side session rotation capability. When untrusted session data (the `pending_cart_id`) is written to the session **before** calling `login_user()`, an attacker can pre-populate the session with a malicious cart ID in their own browser. When the victim later logs in on the same session, the pre-login attacker-controlled value persists into the authenticated session, effectively carrying attacker state forward across the authentication boundary.

The fix moves the session write to occur **after** the successful `login_user()` call. While Flask-Login cannot perform true session-identifier rotation on stock Flask (only server-side session stores provide that), moving the write ensures that any session data written is done so in the context of an authenticated user, preventing pre-login attacker-controlled state from contaminating the authenticated session. The authenticated session is established atomically by `login_user()`, and only subsequent writes to that session come from the authenticated request context.

## Behaviour changes

- Session data is now written after authentication succeeds, not before.
- The authenticated user's cart ID assignment is atomic with their login, eliminating the window where pre-login state could persist.
- No functional change to the user-facing behavior: the cart ID is still carried forward for authenticated users.
- The fix does not require any configuration changes or additional dependencies.
