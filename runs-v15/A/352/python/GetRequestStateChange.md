## Verdict

**CONFIRMED**: The `delete_account` view executes a destructive state change (account deletion) on GET requests without CSRF validation. GET requests are linkable and referable from cross-site contexts, making the account deletion exploitable via CSRF.

## Source

The vulnerability occurs in `views.py` at line 23 where `user.delete()` is called unconditionally from a view:

1. The view accepts all HTTP methods (no restriction)
2. Line 17–19 explicitly document that the operation is triggered via a GET request (`<a href="/account/delete/">`)
3. No CSRF token is validated before the delete operation
4. Django's CSRF middleware does not protect GET requests by design (they are assumed safe)

## Fix

```python
"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods


@login_required
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


@login_required
@require_http_methods(["POST"])
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Expects a POST request with a CSRF token (provided by Django's form handling).
    The template must use a <form method="post"> with {% csrf_token %}.
    """
    user = request.user
    user.delete()
    return redirect("login")


@login_required
def account_orders(request):
    """Read-only order history, unaffected by this finding."""
    orders = request.user.orders.order_by("-created_at")
    return render(request, "account/orders.html", {"orders": orders})
```

## Explanation

**Root Cause**: Destructive operations must never execute on GET requests. GET is stateless and referable—an attacker can trigger it by embedding a link or image in a malicious page or email. CSRF tokens protect POST requests by requiring a value known only to the legitimate session holder; they are not sent automatically by the browser on cross-origin requests.

**How the Fix Works**:
- `@require_http_methods(["POST"])` restricts the view to POST requests only, rejecting GET with HTTP 405 (Method Not Allowed)
- Django's CSRF middleware automatically validates the CSRF token on all POST requests when using forms with `{% csrf_token %}`
- The template (not shown here, but required) must render a form with `method="post"` and the CSRF token tag; the browser will not auto-send this token across origins
- Legitimate users submit the form intentionally; CSRF attacks cannot forge the POST + token combination from another site

**Why This Pattern Matters**: State-changing operations (create, update, delete) must be:
1. POST (or PUT/PATCH/DELETE for REST APIs) only—never GET
2. Protected by a CSRF token that the attacker's browser does not possess
3. Combined with proper authorization checks (already present via `@login_required`)

This is a foundational web security principle; bypassing it enables account takeover, data deletion, and other account-level attacks.
