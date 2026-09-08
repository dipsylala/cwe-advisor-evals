## Verdict

exploitable

- cwe_id: CWE-287 (Improper Authentication)
- location: `FlaskLoginSessionWrittenBeforeLoginUser.py`, line 32
- confidence: high

## Source

`request.form.get("cart_id")`, submitted in the same POST request body as the login credentials on `POST /login`. It is client-supplied on every request to this view, including one sent before the credential check has resolved to a specific verified identity for this call.

## Fix

The sink is `session["pending_cart_id"] = request.form.get("cart_id")` at line 32, which executes before `login_user(user, remember=remember)` at line 34. Per the CWE-287 Python guidance: "never write to `session[...]` before `login_user()`, which would carry pre-login state into the authenticated session." Flask's stock session is a signed client-side cookie with no server-side identifier for Flask-Login to rotate, so the only available mitigation for this ordering hazard is structural: perform every session write for this request only after `login_user()` has established the authenticated session, not before it. As written, the cart-merge value is stapled into the session while the request is still in its pre-authentication state, so any state written there rides along with whatever session context existed prior to authentication succeeding, rather than being scoped to the now-authenticated session.

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
    # Written after login_user() so no pre-authentication session state is
    # carried into the newly authenticated session.
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation

The two statements were reordered: `login_user(user, remember=remember)` now runs first, and `session["pending_cart_id"] = request.form.get("cart_id")` runs after it. This closes the ordering weakness the guidance identifies for Flask-Login on a stock (client-side, cookie-based) session backend: since there is no server-side session identifier for `login_user()` to rotate, the only way to keep pre-authentication session state from bleeding into the authenticated session is to never write session state before the authentication call completes. Moving the write after `login_user()` means the cart-merge key is only ever set in the context of an already-authenticated session, not in a state that existed prior to (and independent of) the credential check succeeding. `login_user()` does not read or depend on `session["pending_cart_id"]`, so the reorder does not change what `login_user()` does or its return value; the redirect target and merge value written to the session are unchanged.

## Behaviour changes

- Statement order: `session["pending_cart_id"] = request.form.get("cart_id")` now executes after `login_user(user, remember=remember)` instead of before it. Reason: this is the fix itself (see Explanation).
- No arguments, return values, status codes, or response bodies changed. `login_user()` is called with the same arguments (`user`, `remember=remember`); the session key, its source expression, and the final `redirect(url_for("storefront.cart"))` are unchanged.
- Verification: `python -m py_compile` against a scratch copy of the fixed file returned no errors (exit 0, no diagnostics). No new imports, names, or dependencies were introduced by this change, so no additional existence check was needed - the fix reorders two pre-existing statements only.
- Assumptions: none. The finding's sink and the applicable fix pattern are both stated explicitly in `cwe/287/python/INDEX.md`, and the file is short enough that the full data flow (source at line 32's `request.form.get("cart_id")` and `request.form.get("email"/"password")`, through the credential check, to the reordered sink) was traced directly by reading the file - no fallback trace procedure was needed.
