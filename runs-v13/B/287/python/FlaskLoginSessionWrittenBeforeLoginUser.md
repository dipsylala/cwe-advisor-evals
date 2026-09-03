## Verdict

Exploitable

## Source

`request.form.get("cart_id")` at line 32 - attacker-controlled form data supplied during login

## Fix

**Vulnerable code:**
```python
# Carry the guest's cart forward so items added before login survive.
# SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
session["pending_cart_id"] = request.form.get("cart_id")

login_user(user, remember=remember)
```

**Fixed code:**
```python
# Authenticate the user first
login_user(user, remember=remember)

# Carry the guest's cart forward so items added before login survive.
session["pending_cart_id"] = request.form.get("cart_id")
```

## Explanation

The vulnerability occurs because session state is being written before authentication completes. In Flask with a client-side signed session cookie, writing to `session` before calling `login_user()` allows the attacker-controlled pre-login session state to be carried into the authenticated session. An attacker can plant a malicious cart_id in their own session, trick a user into authenticating with that session (via session fixation), and have the cart merged into the victim's account. The fix moves the session write to occur after `login_user()` establishes the authenticated context, ensuring pre-login state does not become part of the authenticated session.

## Behaviour changes

None - the session values remain the same; only the order of operations changes to ensure authentication occurs before pre-login data is written to the session. The `login_user()` call on stock Flask uses a signed client-side cookie with no identifier rotation, so the session data survives the call and can be written to afterward.
