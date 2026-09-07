## Verdict

Exploitable. The endpoint accepts GET requests and performs a state-changing operation (`user.delete()`) without CSRF token validation. An attacker can craft a CSRF attack (embedding a malicious link, image, or redirect on an attacker-controlled site) to force an authenticated user to delete their account. The browser automatically includes the user's session cookies, making the request appear legitimate to Django.

## Source

Authenticated HTTP GET request to `/account/delete/` endpoint, delivered via `request` parameter to the `delete_account` view.

## Fix

### File: views.py

```python
"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.http import HttpResponseNotAllowed


@login_required
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


@login_required
def delete_account(request):
    """Permanently delete the signed-in user's account.

    GET renders a confirmation page with a form.
    POST performs the deletion (with CSRF protection via middleware).
    """
    if request.method == 'GET':
        # Render confirmation page that will POST the deletion
        return render(request, "account/delete_confirm.html", {"user": request.user})
    elif request.method == 'POST':
        # Process deletion with CSRF protection (automatic via middleware for POST)
        user = request.user
        user.delete()
        return redirect("login")
    else:
        # Reject other methods
        return HttpResponseNotAllowed(['GET', 'POST'])


@login_required
def account_orders(request):
    """Read-only order history, unaffected by this finding."""
    orders = request.user.orders.order_by("-created_at")
    return render(request, "account/orders.html", {"orders": orders})
```

### File: templates/account/delete_confirm.html

```html
{% extends "base.html" %}

{% block title %}Delete Account Confirmation{% endblock %}

{% block content %}
<div class="confirmation-page">
    <h1>Delete Account</h1>
    <p>Are you sure you want to permanently delete your account? This action cannot be undone.</p>
    
    <form method="post">
        {% csrf_token %}
        <button type="submit" class="btn btn-danger">Yes, Delete My Account</button>
        <a href="{% url 'account_settings' %}" class="btn btn-secondary">Cancel</a>
    </form>
</div>
{% endblock %}
```

## Explanation

The fix applies Django's CSRF protection by moving the state-changing operation from GET to POST. When the user follows the link from the settings page, a GET request to `/account/delete/` now renders a confirmation page containing an HTML form. The form includes `{% csrf_token %}`, which Django's template tag injects the server-controlled CSRF token into the rendered HTML. When the user clicks "Yes, Delete My Account," the form POSTs to the same endpoint, and Django's `CsrfViewMiddleware` automatically validates the token before the deletion code executes. Attackers cannot obtain the token (it is session-bound and never transmitted cross-site), so they cannot forge a valid POST request. The GET request is preserved so existing links from the settings page continue to work without breaking the user experience.

## Behaviour changes

1. **GET requests now return an HTML confirmation page instead of performing immediate deletion.** Reason: Required to satisfy the CSRF protection pattern; confirmation pages are a security best practice for destructive actions and preserve UX for legitimate users following links.

2. **HttpResponseNotAllowed is returned for unsupported methods (PUT, DELETE, PATCH, etc.).** Reason: Explicit method validation prevents accidental or future misuse of the endpoint.

3. **A new template file is required (delete_confirm.html).** Reason: Confirmation pages are part of the CSRF-safe pattern; the template renders the form with the CSRF token that Django's middleware validates on POST.

4. **The actual deletion now requires the CSRF token to be present in the POST request.** Reason: This is the core CSRF protection mechanism; the token is cryptographically bound to the session and cannot be forged or transmitted cross-site by an attacker.
