## Verdict

Confirmed. `update_billing_email` is a state-changing POST endpoint (it queues a billing email change for the authenticated user) that is explicitly opted out of Django's CSRF protection via `@csrf_exempt`, while authentication is based on the ambient session cookie (`request.user.is_authenticated`). Any site can trigger a cross-origin POST from a logged-in victim's browser and the cookie will be sent automatically, since there is no CSRF token check and no other origin verification.

## Source

- File: `views.py`, line 7 (`@csrf_exempt` decorator on `update_billing_email`)
- Sink: `BillingMailer.queue_change(request.user.id, email)` at line 14, reached with `email = request.POST.get("email", "")` taken directly from the unauthenticated-origin request body.
- The endpoint is authenticated only by session cookie (`request.user.is_authenticated`), which is exactly the case Django's CSRF middleware is designed to protect and which `@csrf_exempt` disables here.

## Fix

```python
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from billing_mailer import BillingMailer


@require_POST
def update_billing_email(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

- Remove the `@csrf_exempt` decorator entirely so the view falls back to Django's default CSRF protection (enforced by `CsrfViewMiddleware`, which is on by default in `MIDDLEWARE`).
- Replace the manual `if request.method != "POST"` check with `@require_POST` (from `django.views.decorators.http`) for the same effect with less boilerplate; this is optional but keeps the method restriction was already there and doesn't change behavior.
- The calling page must submit the CSRF token with the POST (e.g. Django's `{% csrf_token %}` template tag in a form, or the `X-CSRFToken` header populated from the `csrftoken` cookie for an AJAX/fetch call, per Django's standard CSRF-cookie JavaScript pattern).
- If this endpoint is only ever called via `fetch`/XHR from the site's own JavaScript rather than a classic form POST, confirm `CSRF_COOKIE_HTTPONLY` is `False` (Django's default) so the client script can read the token cookie, and that `CSRF_USE_SESSIONS` is not enabled in a way that breaks that read.
- If `update_billing_email` is intended to be an API endpoint consumed by a non-browser client with its own auth (API key, bearer token, mutual TLS) rather than the session cookie, use a `SessionAuthentication`-free authentication scheme instead of `@csrf_exempt`, since exempting CSRF only makes sense when the request cannot possibly be replayed by an ambient browser credential.

## Explanation

Django's CSRF protection exists precisely to stop the scenario this view is exposed to: a state-changing request authenticated purely by an automatically-attached session cookie, invoked cross-origin. `@csrf_exempt` disables Django's built-in `CsrfViewMiddleware` check for this view, so a form or `fetch` call hosted on any other origin can silently submit `email` as a POST body field, and the browser will attach the victim's session cookie, satisfying `request.user.is_authenticated` and queuing an attacker-chosen billing email change on the victim's account. Removing the exemption restores the token check the middleware already performs on every unsafe-method request by default, which requires the request to also carry a CSRF token the attacker's page cannot obtain (since it isn't same-origin and can't read the `csrftoken` cookie value protected by same-origin policy). The other logic in the view (auth check, response shape) is unaffected by this change.
