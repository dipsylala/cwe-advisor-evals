## Verdict

Exploitable.

## Source

Unauthenticated request with attacker-controlled email parameter in POST data.

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

The `@csrf_exempt` decorator at line 7 explicitly disables Django's CSRF protection for this state-changing endpoint. This allows an attacker to craft a malicious form on a third-party website that, when submitted by an authenticated user, will change their billing email without their knowledge or consent. Removing `@csrf_exempt` re-enables Django's `CsrfViewMiddleware` protection, which validates a cryptographic CSRF token present in the POST request before processing the state change. The middleware is configured by default in Django settings and automatically protects all POST/PUT/PATCH/DELETE endpoints, including this one.

## Behaviour changes

None. Removing `@csrf_exempt` restores the default CSRF protection without altering the function's logic, return values, or parameters. The endpoint will now require a valid CSRF token in the POST request—either embedded in an HTML form via `{% csrf_token %}` or supplied in an `X-CSRFToken` header for AJAX requests. Legitimate requests from the application's own forms will include this token automatically; cross-site forgery attempts will be rejected.
