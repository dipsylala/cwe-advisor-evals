## Verdict
Confirmed CSRF vulnerability. The endpoint exempts CSRF protection while handling a state-changing POST request from an authenticated user.

## Source
Line 7 in `views.py` applies `@csrf_exempt` decorator to `update_billing_email()`, disabling CSRF token validation. The view accepts user-supplied email data (line 14) and queues a billing email change without verifying request origin.

## Fix
Remove the `@csrf_exempt` decorator from the view function. Replace line 7:

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from billing_mailer import BillingMailer

@csrf_protect
def update_billing_email(request):
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

Alternatively, simply remove the `@csrf_exempt` import and decorator entirely. Django's default middleware applies CSRF protection to all POST requests unless explicitly exempted.

## Explanation
CSRF attacks exploit a browser's automatic credential inclusion to trick authenticated users into performing unwanted actions. An attacker can craft a malicious website with a hidden form that submits to this endpoint, and if the user visits while authenticated, the browser sends valid session cookies, causing an unintended billing email change.

The fix enforces CSRF token validation: POST requests must include a valid `csrftoken` (from either the request body or `X-CSRFToken` header), which the attacker cannot obtain cross-origin. This token is bound to the user's session and prevents the malicious form from succeeding.

Using `@csrf_protect` explicitly or relying on Django's default middleware protection are both acceptable. The key is removing the blanket exemption that introduced this gap.
