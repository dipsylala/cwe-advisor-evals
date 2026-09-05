## Verdict

The vulnerability is confirmed. Line 23 executes an account deletion (state-changing operation) in a GET handler with no CSRF token validation. Django's CSRF middleware only protects POST/PUT/DELETE/PATCH methods, not GET. Since the endpoint is reached via a `<a>` hyperlink (per the comment), a GET request is what actually arrives, bypassing all CSRF protection.

## Source

**File:** evals/cases/352/python/GetRequestStateChange/views.py  
**Lines:** 14–24 (the `delete_account` view)  
**Root Cause:** The state-changing operation (user deletion) is implemented as a GET endpoint. Django's `CsrfViewMiddleware` only validates POST/PUT/DELETE/PATCH requests, not GET. A cross-site attacker can forge an authenticated GET request to `/account/delete/` (e.g. via an `<img>` tag, form submission with GET, or redirect) to delete the victim's account.

## Fix

Replace the single `delete_account` view with two endpoints: a GET handler that renders a confirmation page, and a POST handler that processes the deletion with CSRF token validation.

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
@require_http_methods(["GET"])
def delete_account_confirm(request):
    """Display account deletion confirmation page.
    
    Renders a form that POSTs (with CSRF token) to delete_account_process.
    """
    return render(request, "account/delete_confirm.html", {"user": request.user})


@login_required
@require_http_methods(["POST"])
def delete_account_process(request):
    """Permanently delete the signed-in user's account.
    
    Requires POST with valid CSRF token (validated automatically by
    CsrfViewMiddleware). The token is included via {% csrf_token %} in the
    confirmation form.
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

**urls.py** routing:
```python
from django.urls import path
from . import views

urlpatterns = [
    path("settings/", views.account_settings, name="account_settings"),
    path("delete/", views.delete_account_confirm, name="delete_account_confirm"),
    path("delete/process/", views.delete_account_process, name="delete_account_process"),
    path("orders/", views.account_orders, name="account_orders"),
]
```

**Template account/delete_confirm.html**:
```html
{% extends "base.html" %}
{% load static %}

{% block content %}
<h1>Delete Account</h1>
<p>This action cannot be undone. All your data will be permanently deleted.</p>

<form method="post" action="{% url 'delete_account_process' %}">
    {% csrf_token %}
    <button type="submit" class="btn btn-danger">Confirm Deletion</button>
    <a href="{% url 'account_settings' %}">Cancel</a>
</form>
{% endblock %}
```

**settings.py** (if not already present):
```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",  # CSRF protection enabled
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = True
```

## Explanation

1. **Separate confirmation and deletion**: Moving the deletion to a POST endpoint allows Django's `CsrfViewMiddleware` to validate the CSRF token. The GET endpoint becomes a confirmation page that renders the destructive form.

2. **CSRF Token Inclusion**: The confirmation form includes `{% csrf_token %}`, which Django automatically embeds as a hidden field and injects into the POST request headers. The middleware validates it before `delete_account_process` runs.

3. **Method Enforcement**: `@require_http_methods` guards each endpoint to its intended HTTP method, preventing accidental GET access to the deletion handler.

4. **SameSite Cookies**: `SESSION_COOKIE_SAMESITE='Strict'` and `CSRF_COOKIE_SAMESITE='Strict'` provide defense-in-depth by preventing the browser from including cookies in cross-site requests, even if a CSRF filter is misconfigured.

5. **Existing Links Preserved**: The original `/account/delete/` URL still exists (now mapped to the confirmation view). Existing hyperlinks pointing to it will now land on the confirmation page instead of immediately deleting the account, which is a safer behaviour change than silently processing deletions without tokens.

## Behaviour changes

- **Before**: A GET to `/account/delete/` immediately deleted the account with no confirmation or token validation. An attacker's page could trigger deletion via `<img src="https://victim.example/account/delete/">`.
- **After**: A GET to `/account/delete/` (unchanged URL) renders a confirmation page asking the user to confirm. Only a POST to `/account/delete/process/` with a valid CSRF token (signed by the session cookie and included via the form) actually deletes the account. Existing links to `/account/delete/` remain valid but now require an additional user action (button click on the confirmation form).
