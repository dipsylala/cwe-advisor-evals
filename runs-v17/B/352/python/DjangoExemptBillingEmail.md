## Verdict

Exploitable - The `@csrf_exempt` decorator explicitly disables CSRF protection on a state-changing POST endpoint that modifies user account data (billing email), allowing attackers to forge requests from authenticated users.

## Source

Attacker-controlled website visited by an authenticated user, requesting `POST /update_billing_email` with a malicious email address.

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

The `@csrf_exempt` decorator has been removed, which explicitly bypassed Django's CSRF middleware. Removing it restores automatic CSRF token validation to this state-changing endpoint. Django's `CsrfViewMiddleware` (when enabled globally, which is the default) will now require a valid CSRF token in all POST requests to this view. The token is automatically included by Django forms via `{% csrf_token %}` and can be extracted and sent via the `X-CSRFToken` header for AJAX requests. The unused import of `csrf_exempt` has also been removed.

## Behaviour changes

None - Removing CSRF exemption leaves the function's return contract, error handling, and data flow intact. The only change is that requests must now include a valid CSRF token, which is the correct security requirement for state-changing operations. Legitimate requests from the application's own forms or AJAX handlers (sending the token) will continue to work; forged cross-site requests will be rejected with a 403 Forbidden response by the middleware.
