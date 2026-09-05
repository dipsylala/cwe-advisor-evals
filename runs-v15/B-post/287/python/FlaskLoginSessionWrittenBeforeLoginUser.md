## Verdict
Exploitable

## Source
`request.form.get("cart_id")` - attacker-controlled form parameter

## Sink
`session["pending_cart_id"] = request.form.get("cart_id")` at line 32, executed before `login_user()` is called

## Fix

**Vulnerable code (lines 30-36):**
```python
    # Carry the guest's cart forward so items added before login survive.
    # SAST FINDING: CWE-287 (Improper Authentication) reported here. Sink is the next statement.
    session["pending_cart_id"] = request.form.get("cart_id")

    login_user(user, remember=remember)

    return redirect(url_for("storefront.cart"))
```

**Fixed code (lines 30-36):**
```python
    # Carry the guest's cart forward so items added before login survive.
    login_user(user, remember=remember)
    
    session["pending_cart_id"] = request.form.get("cart_id")

    return redirect(url_for("storefront.cart"))
```

## Explanation
The vulnerability is that untrusted form data is written to `request.session` before `login_user()` establishes authentication. This allows pre-login state to persist into the authenticated session. By moving the session write to after `login_user()`, the session modification occurs only after the user is authenticated, ensuring that the session data belongs to the authenticated context rather than carrying over untrusted pre-login values. The `login_user()` function manages the session lifecycle for Flask-Login, and any session writes must occur after it is called to maintain the authentication boundary.

## Behaviour changes
None. The cart_id value is stored in session after login either way; moving the write after `login_user()` only changes when it is written relative to authentication, not what value is stored or how it is later retrieved.
