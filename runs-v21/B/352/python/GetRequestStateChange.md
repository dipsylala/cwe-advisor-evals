## Verdict

exploitable

## Source

Authenticated user session (`request.user`) making a GET request to the `delete_account` view.

## Fix

The vulnerability stems from performing a state-changing operation (account deletion) in response to unauthenticated GET requests. Django's CSRF middleware only protects non-safe HTTP methods (POST, PUT, DELETE), so GET requests bypass protection entirely. 

The fix splits the operation into two endpoints:
1. A GET endpoint that renders a confirmation page
2. A POST endpoint that performs the actual deletion with automatic CSRF token validation

The form on the confirmation template must include Django's `{% csrf_token %}` tag, which is automatically validated by `CsrfViewMiddleware`.

### File: views.py

```python
"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods


@login_required
@require_http_methods(["GET"])
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


@login_required
@require_http_methods(["GET"])
def delete_account(request):
    """Render a confirmation page for account deletion.

    The actual deletion is handled by the POST endpoint.
    """
    return render(request, "account/delete_confirm.html", {"user": request.user})


@login_required
@require_http_methods(["POST"])
def delete_account_confirm(request):
    """Permanently delete the signed-in user's account after confirmation.

    Handles POST requests with CSRF token validation performed automatically
    by Django's CsrfViewMiddleware. The form on delete_confirm.html submits
    to this endpoint.
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

The original code performed account deletion in response to GET requests without CSRF protection. Django's CSRF middleware only validates tokens on non-safe methods (POST, PUT, DELETE), making GET requests unprotected—an attacker could craft a URL to `GET /account/delete/` that forces an authenticated user's browser to perform the deletion when visiting a malicious site.

The fix implements the Synchronizer Token Pattern by moving the state-changing operation from GET to POST. The `delete_account` view now renders a confirmation page, and the new `delete_account_confirm` endpoint handles the actual deletion. Django's `CsrfViewMiddleware` automatically validates the CSRF token on POST requests when the form includes `{% csrf_token %}` in the confirmation template. The `@require_http_methods` decorators explicitly enforce that each endpoint accepts only its intended method, preventing method confusion.

## Behaviour changes

1. The GET `/account/delete/` endpoint now returns an HTML confirmation page instead of immediately deleting the account. Users must submit a form to confirm deletion.
2. A new POST endpoint is required to handle the actual deletion (registered in `urls.py` as a separate route, e.g., `POST /account/delete/confirm/`).
3. Existing direct links to `/account/delete/` now render a confirmation page instead of immediately deleting. Any email links, documentation, or bookmarks pointing to this URL will now show a confirmation page—users must click "Confirm" to proceed. This is a behaviour change from the original flow but is the standard safe pattern for state-changing operations.
4. The confirmation template must include Django's `{% csrf_token %}` tag in the form for token validation to work.
