## Verdict

**VULNERABLE** — The `@csrf_exempt` decorator on the `update_billing_email` view disables CSRF protection for a state-modifying POST endpoint, allowing an attacker to forge requests that change a user's billing email without their consent.

## Source

**File:** `evals/cases/352/python/DjangoExemptBillingEmail/views.py`  
**Line:** 7

The vulnerable code:
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

The `@csrf_exempt` decorator at line 7 explicitly exempts this endpoint from Django's CSRF protection. Since the endpoint is accessible from a cross-origin context and modifies account data (billing email), this creates a CSRF vulnerability where an attacker can trick an authenticated user into unknowingly changing their billing email.

## Fix

Remove the `@csrf_exempt` decorator:

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

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

Additionally, the client making the POST request must include the CSRF token in the request. For JSON endpoints, this is typically done via the `X-CSRFToken` header, which Django automatically validates once the `@csrf_exempt` decorator is removed. The CSRF token is available to the client through the `csrftoken` cookie (set by Django) or rendered in the page.

## Explanation

Django provides built-in CSRF protection that automatically validates a CSRF token for all state-modifying requests (POST, PUT, DELETE, PATCH) unless explicitly exempted. The `@csrf_exempt` decorator should only be used for endpoints that deliberately need to accept cross-origin requests without CSRF validation (such as webhook receivers that cannot store cookies), not for user-facing endpoints that modify account data.

By removing `@csrf_exempt`, Django's middleware will:
1. Require a valid CSRF token in the request (from the `X-CSRFToken` header, POST data, or cookie)
2. Automatically reject requests that lack or provide an invalid token
3. Prevent attackers from forging requests on behalf of authenticated users

Since this endpoint is intended for authenticated users modifying their own billing email, standard CSRF protection is both appropriate and necessary.
