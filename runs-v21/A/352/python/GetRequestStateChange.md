## Verdict

Valid. The view performs a state-changing operation (account deletion) in response to an unauthenticated GET request without CSRF token validation. A malicious site can trigger account deletion by linking to the endpoint or embedding an image with that URL, silently deleting the victim's account.

## Source

File: `views.py`, line 23

The `delete_account` view accepts GET requests (no method restriction in the view or URL registration) and immediately calls `user.delete()` without requiring a CSRF token. The comment on line 17-19 confirms the vulnerability: the view is called via a plain `<a>` tag, which issues a GET request.

## Fix

### File: views.py

```python
"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods


@login_required
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


@login_required
@require_http_methods(['POST'])
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Accepts only POST requests with a valid CSRF token from the settings page.
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

The fix restricts the view to POST requests only by adding `@require_http_methods(['POST'])`. This forces clients to submit an HTML form instead of following a plain link.

Django's CSRF middleware automatically validates CSRF tokens for POST requests. When the form is rendered in the template with `{% csrf_token %}`, Django includes a unique token tied to the user's session. On submission, the middleware verifies the token matches before allowing the request to proceed.

A cross-origin attacker cannot obtain the CSRF token (browser same-origin policy blocks access to the response), so they cannot craft a valid POST request. This blocks the silent deletion attack while preserving legitimate account deletion from the settings page.

The `@login_required` decorator ensures only authenticated users can access the view, and the POST-only restriction eliminates the CSRF window.
