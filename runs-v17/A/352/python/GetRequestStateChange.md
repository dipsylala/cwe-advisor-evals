## Verdict

The finding is confirmed. The `delete_account` view performs a state-changing operation (account deletion) in response to unauthenticated GET requests, exposing it to CSRF attacks. An attacker can trick a logged-in user into visiting a URL that deletes their account by embedding the link in an img tag, fetching from a malicious site, or other cross-origin techniques.

## Source

The vulnerable code at line 23 in `views.py`:

```python
@login_required
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Linked from the settings page as a plain <a href="/account/delete/">
    so the browser issues a GET request. urls.py registers this view with
    no method restriction, so GET is what actually reaches it.
    """
    user = request.user
    # SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    user.delete()
    return redirect("login")
```

The vulnerability: state-changing operations must never be accessible via GET requests, because GET requests:
- Include the user's session cookies automatically (per HTTP/browser spec)
- Cannot be protected by CSRF tokens (no standard way to include a token in a GET URL safely)
- Can be triggered cross-origin without user knowledge

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
@require_http_methods(["POST"])
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Requires a POST request with a valid CSRF token.
    The account settings template must submit via <form method="post"> with {% csrf_token %}.
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

**Why the fix works:**

1. **`@require_http_methods(["POST"])`** restricts the view to POST requests only. GET requests now receive a 405 Method Not Allowed response.

2. **Django's CSRF middleware** (`django.middleware.csrf.CsrfViewMiddleware`, enabled by default) automatically protects POST, PUT, DELETE, and PATCH requests by:
   - Requiring a valid CSRF token from `request.POST` or headers
   - Rejecting requests without the token or with an invalid token

3. **GET requests cannot carry CSRF tokens** in the standard way, which is why GET must never perform state changes. State changes must use POST/PUT/DELETE/PATCH.

**Template adjustment required:**

The `account/settings.html` template must change from a plain link to a form:

```html
<!-- Before (vulnerable) -->
<a href="/account/delete/">Delete Account</a>

<!-- After (protected) -->
<form method="post" action="/account/delete/">
  {% csrf_token %}
  <button type="submit">Delete Account</button>
</form>
```

The `{% csrf_token %}` template tag injects a hidden field with the CSRF token. When the form submits via POST, the token is validated by the middleware before reaching the view.

**Defense layers:**

- **Primary**: Changing GET → POST eliminates the cross-origin request attack vector
- **Secondary**: CSRF token validation ensures the request originated from the application itself, not a malicious cross-site context
