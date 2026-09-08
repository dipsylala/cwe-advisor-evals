## Verdict

Confirmed. `delete_account` performs a permanent, irreversible state change (deleting the signed-in user's account) and is reachable via a plain `GET` request: the docstring says it is linked as `<a href="/account/delete/">` and `urls.py` registers no method restriction. Django's CSRF middleware does not protect `GET` requests at all - it only validates the token on unsafe methods when the view actually requires one of them - so a `GET`-triggered state change gets no CSRF protection regardless of middleware configuration. An attacker can trigger it purely with a cross-site navigation or an auto-loading resource (e.g. `<img src="https://victim-site/account/delete/">`) embedded on a page the victim visits while authenticated, with no token needed.

## Source

`request` reaching `delete_account` in `views.py` (line 14) via an unauthenticated-method GET, terminating at `user.delete()` on line 23.

## Fix

### File: views.py
```python
"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST


@login_required
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


@login_required
@require_POST
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Must be triggered via a POST form (not a plain <a href> link) so that
    Django's CSRF middleware validates the request token before this view
    runs. urls.py continues to register this view with no method
    restriction of its own; require_POST enforces the method here and
    returns 405 for GET.
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

The vulnerability has two parts, and closing only one leaves the other exploitable:

1. **Method**: the view had no method restriction, so the state-changing `delete()` ran on a `GET`. `@require_POST` (from `django.views.decorators.http`) makes `GET` requests fail with `405 Method Not Allowed` before `user.delete()` executes, and it composes safely with `@login_required` already present on every view in this file.
2. **CSRF token**: Django's `CsrfViewMiddleware` (enabled by default in `MIDDLEWARE` in a standard Django project) validates the CSRF token only on requests using unsafe HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`). Once the view is restricted to `POST`, that middleware's existing token check applies to it for the first time and blocks a cross-site forgery. This requires no code change in this file, but it does require the linked template to change from a plain `<a href="/account/delete/">` anchor to a `<form method="post">` containing `{% csrf_token %}` and a submit control - fixing the view alone without changing the template's `<a>` link would leave the endpoint unreachable from the UI while still being a `GET`-based CSRF path if any other caller mistakenly issues a `GET`, so both must move together. `urls.py`'s lack of a method restriction is untouched and remains fine, since Django resolves the URL before dispatch decides whether the method is allowed.

Verification: after the fix, a `GET /account/delete/` (including via an attacker-hosted auto-loading `<img>` or cross-site link) returns `405` and the account is not deleted. A legitimate `POST /account/delete/` submitted from the site's own settings form, carrying the CSRF cookie/token pair, succeeds and redirects to `login`. A forged cross-site `POST` (e.g. from an attacker's page auto-submitting a form) fails CSRF validation with `403 Forbidden` because it cannot supply the victim's CSRF token.
