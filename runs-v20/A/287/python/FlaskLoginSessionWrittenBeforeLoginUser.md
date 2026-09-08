## Verdict

Confirmed. The handler writes to the session (line 32) before calling `login_user()` (line 34), so the guest (pre-authentication) session is carried across the authentication boundary unmodified rather than being replaced by a freshly established, authenticated session.

## Source

`auth_bp.route("/login")` in `FlaskLoginSessionWrittenBeforeLoginUser.py`. The relevant flow:

- `request.form.get("cart_id")` (attacker/client-controlled) is written straight into `session["pending_cart_id"]` at line 32, while the session at that point is still the pre-authentication guest session.
- `login_user(user, remember=remember)` at line 34 then layers the authenticated identity (`_user_id`, `_fresh`, `_id`, etc.) on top of that same, unrotated session object.

Flask-Login does not rotate or regenerate the underlying Flask session on its own; it only adds keys to whatever session dict already exists. Because nothing clears or regenerates the session before `login_user()` runs, any state established in the session prior to a successful login (including state an attacker fixated there, e.g. via a session-fixation setup or cross-subdomain cookie tossing) persists unchanged into the now-authenticated session instead of being invalidated at the privilege boundary.

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

    # Capture the guest's cart id before the pre-authentication session is
    # discarded, so it can be carried into the new authenticated session.
    cart_id = request.form.get("cart_id")

    # Discard the pre-authentication session before establishing the
    # authenticated one. Flask-Login does not rotate the session itself, so
    # anything written to session state before this point (including this
    # request's own guest session) would otherwise survive unchanged across
    # the login boundary. This must run before login_user() and before any
    # other session write.
    session.clear()

    login_user(user, remember=remember)

    # Carry the guest's cart forward now that it is part of the freshly
    # established, authenticated session rather than the discarded one.
    session["pending_cart_id"] = cart_id

    return redirect(url_for("storefront.cart"))
```

## Explanation

The fix moves the session-fixation boundary to the correct place: `session.clear()` runs immediately after credentials are verified and before any data is written into the session, so the guest session's contents are discarded rather than inherited by the authenticated session. `login_user()` then populates the session's authenticated keys (`_user_id`, `_fresh`, `_id`, and the remember-cookie flag) on a clean session. The `cart_id` value is read from the request before the clear (so the legitimate guest cart is not lost) but is written back into `session["pending_cart_id"]` only after `login_user()` has run, so it becomes part of the new authenticated session rather than a holdover from the pre-authentication one. No behavior changes for a legitimate login: the cart id still merges into the account exactly as before, and invalid credentials still short-circuit at the existing check with no session mutation at all.
