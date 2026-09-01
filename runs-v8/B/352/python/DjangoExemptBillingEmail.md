## Verdict

Real vulnerability confirmed. The endpoint disables CSRF protection on a state-changing operation that modifies authenticated user data.

## Source

**File:** views.py, line 7

```python
@csrf_exempt
def update_billing_email(request):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

The `@csrf_exempt` decorator at line 7 disables CSRF protection for this POST endpoint that queues a billing email change for authenticated users.

## Fix

Remove the `@csrf_exempt` decorator and its import. Let Django's `CsrfViewMiddleware` (which should be globally enabled in settings) handle automatic CSRF token validation.

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

The `@csrf_exempt` decorator explicitly disables CSRF protection for this endpoint. An attacker can exploit this by crafting a malicious webpage that, when visited by an authenticated user, silently performs a POST request to change the user's billing email without their consent. Django's `CsrfViewMiddleware` provides automatic CSRF token validation for all state-changing requests (POST, PUT, DELETE, PATCH), so removing the exemption is sufficient to protect this endpoint.

The authentication check (`request.user.is_authenticated`) does not provide CSRF protection—it only verifies the user is logged in. CSRF attacks work precisely because the attacker's malicious request carries the victim's valid session credentials; authentication alone cannot distinguish a legitimate request from a forged one.

## Behaviour changes

**Before:** POST requests to `/update_billing_email` are processed regardless of origin, allowing cross-site request forgery. Any authenticated user visiting a malicious site can have their billing email changed without consent.

**After:** POST requests must include a valid CSRF token (automatically validated by Django middleware). Forged requests from external sites lack the token and are rejected with a 403 Forbidden response. Legitimate requests from within the application provide the token via form submission or AJAX headers (automatically handled by Django templates and fetch/axios when configured correctly).
