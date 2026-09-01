## Verdict
VULNERABLE

## Source
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

## Fix
```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from billing_mailer import BillingMailer


@require_http_methods(["POST"])
def update_billing_email(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "unauthorized"}, status=401)

    email = request.POST.get("email", "")
    BillingMailer.queue_change(request.user.id, email)
    return JsonResponse({"status": "queued"})
```

## Explanation
The `@csrf_exempt` decorator disables Django's built-in CSRF protection. This view modifies a user's billing email—sensitive state that affects account security—while accepting POST requests from authenticated users. Without CSRF token validation, an attacker can forge a request in the victim's browser to change their billing email to an attacker-controlled address, enabling account takeover or email-based account recovery attacks.

The fix removes `@csrf_exempt` to restore CSRF token validation. Django's default middleware automatically validates CSRF tokens on all unsafe HTTP methods (POST, PUT, DELETE, PATCH) for authenticated users. The manual method check is redundant with `@require_http_methods`, which enforces only POST is accepted.
