## Verdict

Confirmed. `delete_account` mutates state (permanently deletes the signed-in user's account) but is reachable by GET, since `urls.py` registers it with no method restriction and the settings page links to it with a plain `<a href="/account/delete/">`. Django's `CsrfViewMiddleware` only validates unsafe methods (POST/PUT/PATCH/DELETE) - a GET request is never subject to CSRF-token checks regardless of whether the middleware is enabled. An attacker can therefore trigger account deletion for any logged-in victim with a simple cross-site GET (an `<img src="https://target/account/delete/">`, a redirect, or a prefetched link) with no token to steal or forge.

## Source

Any cross-site page the victim's browser loads while an authenticated session cookie is active - no form submission or JavaScript is required, since the request is a plain GET. `request` in `delete_account` is the entry point; `request.user` resolves via the ambient session cookie, not anything the request itself must prove.

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
def delete_account_confirm(request):
    """Render a confirmation page whose form POSTs to delete_account.

    urls.py should route the existing /account/delete/ link here (GET).
    This view only renders a page; it never mutates state, so it is safe
    for a plain <a href="..."> to keep reaching it directly.
    """
    return render(request, "account/delete_confirm.html")


@login_required
@require_POST
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Only reachable by POST (enforced by @require_POST, which returns
    HTTP 405 for any other method). Because CSRF middleware only
    validates non-safe methods, restricting this view to POST is what
    puts it back under CsrfViewMiddleware's protection; the confirmation
    page's <form method="post"> with {% csrf_token %} is the only caller
    that should submit here. urls.py should map a new path (e.g.
    /account/delete/confirm/) to this view.
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

The vulnerability is the verb, not a missing token: adding a CSRF token to a GET route does nothing, because `CsrfViewMiddleware` never checks safe methods in the first place. The fix moves the actual state change onto POST by adding `@require_POST` to `delete_account`, which brings it under CSRF middleware's enforcement and makes any non-POST request fail closed with HTTP 405 instead of deleting the account. Since the settings page's existing plain `<a href="/account/delete/">` can only issue a GET, and changing that URL's method would silently break the link, a new `delete_account_confirm` view takes over the GET at that URL, rendering a confirmation page whose own `<form method="post">` (carrying `{% csrf_token %}`) is the only thing that legitimately reaches `delete_account`. This assumes `CsrfViewMiddleware` is enabled globally in Django settings, which is Django's project-template default; `settings.py` is outside this file's call chain and was not modified, so that assumption should be verified against the project's actual `MIDDLEWARE` list. Wiring this up fully also requires `urls.py` (not part of the supplied call chain) to route the pre-existing `/account/delete/` path to `delete_account_confirm` and add a new POST-only path (e.g. `/account/delete/confirm/`) to `delete_account`, and requires a new `account/delete_confirm.html` template with the confirmation form - both called out below since they sit outside the file being fixed.

## Behaviour changes

- A direct GET to the URL currently mapped to `delete_account` (e.g. clicking the existing settings-page link) no longer deletes the account; it now needs to be routed (in `urls.py`, not shown) to the new `delete_account_confirm` view, which renders a confirmation page instead.
- `delete_account` now requires POST and returns HTTP 405 for any other method; the only intended caller is the confirmation page's own form submission.
- A new template, `account/delete_confirm.html`, is required (containing a `<form method="post" action="...">` with `{% csrf_token %}` and a submit control) - not included here since templates are outside the supplied call chain.
- `urls.py` needs a corresponding update: keep the pre-existing URL name/path pointing at `delete_account_confirm` (GET) and add a new path for the POST-only `delete_account`. Until that routing change ships alongside this file, the settings-page link will resolve to the confirmation view with no route yet defined for the POST target.
