## Verdict

Exploitable. Confidence: high.

- CWE ID: CWE-352 (Cross-Site Request Forgery)
- Location: `views.py`, line 7-8 (`@csrf_exempt` on `update_billing_email`)
- Source: the request body (`request.POST.get("email", "")`), submitted by whatever browser the authenticated user's session cookie is attached to
- Sink: `BillingMailer.queue_change(request.user.id, email)`, a state-changing operation (queues a change to the user's billing email) reached via a `@csrf_exempt` POST view

## Source

`request.POST.get("email", "")` in `update_billing_email` (`views.py` line 14) - attacker-controlled request body, submitted cross-site.

## Fix

### File: views.py

```python
from django.http import JsonResponse

from billing_mailer import BillingMailer


def update_billing_email(request):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

## Explanation

`update_billing_email` is a POST-only, authenticated, state-changing endpoint (it queues a change to the user's billing email), so it is exactly the kind of route Django's CSRF protection exists to cover. The `@csrf_exempt` decorator removes that view from `CsrfViewMiddleware`'s check entirely, so any cross-origin page can submit a form or fetch request to this URL and, riding the victim's session cookie, queue an arbitrary billing-email change with no proof the request came from the application's own UI. The fix removes the decorator (and its now-unused import) so the view falls back to Django's default CSRF enforcement: `CsrfViewMiddleware` will reject the POST unless it carries a valid token bound to the user's session, closing the forgery path while leaving the existing method, authentication, and business logic untouched. This assumes `django.middleware.csrf.CsrfViewMiddleware` is present in the project's `MIDDLEWARE` setting - it is Django's shipped default and nothing in this endpoint suggests it was removed project-wide; the case does not include `settings.py`, so this is stated as an assumption rather than confirmed.

## Behaviour changes

- Removed the `csrf_exempt` import and decorator; no other line changed. `request.method`, authentication, `request.POST.get("email", "")`, the call to `BillingMailer.queue_change`, and both JSON responses are identical to the original.
- Client-visible effect: callers must now send a valid CSRF token with the POST (Django's standard mechanism - the `csrftoken` cookie value echoed back in the `X-CSRFToken` header for an AJAX/fetch caller, or a `csrfmiddlewaretoken` form field for a template-rendered form). A caller that omits the token now receives Django's standard `403 Forbidden` CSRF-failure response instead of reaching this view. This is the intended effect of the fix, not incidental scope creep - it is the mechanism that closes the forgery path.
- Assumption: `CsrfViewMiddleware` is enabled in the project's Django `MIDDLEWARE` (the framework default); not verified here because `settings.py` is outside the two files in this case. If it were disabled, removing `@csrf_exempt` alone would not restore protection.
- Verification: copied the fixed file to a scratch location and ran `python -m py_compile` against it - compiled with no errors (exit 0). No Django runtime/settings were available in this environment to execute the view or exercise the middleware directly.
