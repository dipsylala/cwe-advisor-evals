## Verdict
CONFIRMED. The endpoint is vulnerable to CSRF because `@csrf_exempt` disables Django's built-in CSRF protection. An attacker can forge a request to change an authenticated user's billing email without their knowledge.

## Source
The vulnerability is on line 7 of `views.py`: the `@csrf_exempt` decorator on `update_billing_email` disables CSRF token validation for a state-changing POST endpoint.

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
The fix removes the `@csrf_exempt` decorator and the import of `csrf_exempt`, which re-enables Django's automatic CSRF protection for this endpoint.

**How this stops the attack:**
1. Django now requires all POST requests to include a valid CSRF token
2. The token is bound to the user's session and the origin site
3. Attacker-controlled pages cannot obtain or forge this token
4. Forged requests from malicious sites are automatically rejected

**Authentication alone is not sufficient for CSRF prevention:** Checking `request.user.is_authenticated` verifies the user's identity, but doesn't prevent an attacker from making requests on their behalf. CSRF protection validates that the request originated from your own application, not an attacker's page.

**Implementation details:**
- The CSRF token must be included in POST requests from your own forms (via `{% csrf_token %}` template tag)
- JavaScript requests must read the token from cookies or HTML and include it in the request
- Django's `CsrfViewMiddleware` (enabled by default) enforces this validation
- The endpoint continues to reject unauthenticated requests, providing defense in depth
