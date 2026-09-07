## Verdict

Exploitable. Untrusted guest cart ID is written to the session before user authentication and before login_user() establishes the authenticated session, allowing the pre-login session state to be carried into the authenticated session.

## Source

- **Source**: `request.form.get("cart_id")` (line 32) - untrusted user-supplied cart ID from form input
- **Sink**: `session["pending_cart_id"] = ...` (line 32) - session write before authentication
- **Data flow**: Guest-supplied form parameter flows directly into session storage before login_user() is called, violating the principle that session writes must follow, not precede, authentication

## Fix

**Vulnerable code (lines 31-34):**
```python
    # Carry the guest's cart forward so items added before login survive.
    # SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
    session["pending_cart_id"] = request.form.get("cart_id")

    login_user(user, remember=remember)
```

**Fixed code:**
```python
    # Carry the guest's cart forward so items added before login survive.
    login_user(user, remember=remember)
    session["pending_cart_id"] = request.form.get("cart_id")
```

## Explanation

Moving the session write to occur after `login_user()` ensures that the authenticated session is established and protected before guest state is merged into it. Flask-Login with client-side signed cookies has no server-side session rotation mechanism, so pre-login session values would be carried into the authenticated session unchanged. By writing to the session only after `login_user()` completes, the cart ID is associated with the authenticated user's session from the point it is stored, preventing session fixation and state-taint attacks where an attacker plants a malicious cart ID in a guest session that later becomes an authenticated session.

## Behaviour changes

No functional behaviour changes. The cart ID is still written to the session and passed forward to the storefront, but now it is guaranteed to be written only after the user is authenticated. The order change ensures defence-in-depth: authentication is verified and the authenticated session is in place before any guest-supplied state can be bound to the user's identity.
