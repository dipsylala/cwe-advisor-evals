## Verdict

Exploitable. Confidence: high.

`update_billing_email` is a POST-only, session-authenticated, state-changing endpoint (`request.user.is_authenticated` implies session-cookie auth) that carries `@csrf_exempt`, so it is excluded from Django's `CsrfViewMiddleware`. A cross-site page can submit a same-origin-looking POST that rides the victim's session cookie, and the server will accept it with no proof the request originated from the application.

## Source

`request` (the inbound HTTP POST) at `views.py:8`, specifically `request.POST.get("email", "")` at `views.py:14` - fully attacker-controlled when the request is forged from a third-party page, since no CSRF token is required to reach this line.

## Fix

Vulnerable code (`views.py`):

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from billing_mailer import BillingMailer


@csrf_exempt  # exempts a state-changing POST endpoint from CSRF validation
def update_billing_email(request):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

Fixed code (`views.py`):

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

Corresponding template/AJAX callers must send the CSRF token: include `{% csrf_token %}` in any HTML form that posts to this view, or read the `csrftoken` cookie and send it in the `X-CSRFToken` header for AJAX/fetch calls, per Django's standard CSRF flow. This assumes the project has not also excluded this path from `MIDDLEWARE`'s `CsrfViewMiddleware` or `CSRF_TRUSTED_ORIGINS`/exclusion lists elsewhere; only the file in scope was available to trace.

## Explanation

The `@csrf_exempt` decorator and its now-unused import are removed, which is the only change. With the decorator gone, this view is once again subject to Django's globally-enabled `CsrfViewMiddleware` (assumed enabled, per Django's default `MIDDLEWARE`, since no evidence to the contrary was in scope): a POST request must carry a valid, session-bound CSRF token or the middleware rejects it with `403 Forbidden` before `update_billing_email` ever runs. This closes the weakness because the token can only be read by same-origin JavaScript or a form rendered by the application itself, so a forged cross-site POST built from the victim's session cookie alone no longer succeeds. The existing authentication check (`request.user.is_authenticated`) is left in place; it establishes *who* the caller is but never proved the request was intentional, which is precisely the gap CSRF protection closes.

## Behaviour changes

None beyond the CSRF enforcement itself, which is the fix. Method handling, authentication check, status codes (405/401), the call to `BillingMailer.queue_change(request.user.id, email)`, and the success response are all unchanged. The one externally visible effect is that POST requests to this endpoint must now include a valid CSRF token (form tag or `X-CSRFToken` header) or receive `403 Forbidden` from the middleware - any existing caller (browser form, AJAX script, or non-browser API client) that was previously omitting the token will need to start sending it.
