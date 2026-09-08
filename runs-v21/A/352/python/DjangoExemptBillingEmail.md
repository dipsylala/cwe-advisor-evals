## Verdict
Real CSRF vulnerability. The `@csrf_exempt` decorator disables Django's CSRF protection on a state-changing endpoint that performs a sensitive operation (billing email modification) on behalf of an authenticated user.

## Source
views.py line 7: `@csrf_exempt` decorator on `update_billing_email()` function.

The vulnerability allows an attacker to forge a request that changes an authenticated user's billing email without the user's knowledge, by embedding a malicious form or fetch call in a third-party site the user visits.

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
The `@csrf_exempt` decorator is removed, restoring Django's default CSRF protection. This forces any legitimate request to include a valid CSRF token, which:

1. Django's CSRF middleware verifies automatically before the view runs
2. Can only be obtained from a page served by the same origin (via the `{% csrf_token %}` template tag or the `CSRF-Token` header)
3. An attacker on a different site cannot obtain the token, so forged cross-site requests will be rejected

Authentication alone (`request.user.is_authenticated`) is insufficient to prevent CSRF—an attacker exploits the fact that the user's browser automatically sends their session cookie. CSRF tokens close this gap by requiring proof that the request originated from the application's own UI.

Since `request.POST` is used, the CSRF token will be verified by Django's middleware (`django.middleware.csrf.CsrfViewMiddleware`), assuming it is enabled in `MIDDLEWARE` (the default for new Django projects).
