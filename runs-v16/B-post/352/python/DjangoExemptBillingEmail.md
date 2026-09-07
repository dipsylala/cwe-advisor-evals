## Verdict
**Exploitable.** The endpoint disables CSRF protection on a state-changing operation that modifies authenticated user data. An attacker can craft a malicious request to change a victim's billing email without the victim's knowledge, exploiting their active session.

## Source
Line 14: `email = request.POST.get("email", "")` - attacker-controlled input from the HTTP request body.

## Fix
Remove the `@csrf_exempt` decorator from line 7. The corrected code:

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
The `@csrf_exempt` decorator explicitly disables Django's CSRF protection for this view. Removing it restores protection by Django's `CsrfViewMiddleware` (enabled by default in Django projects). With the decorator removed, the view will now validate the CSRF token present in the request before processing the state-changing POST. Clients must include a valid CSRF token in their POST request - Django's form template tag `{% csrf_token %}` or, for AJAX requests, the token read from the cookie and sent in the `X-CSRFToken` header. Without a valid token, Django rejects the request with a 403 Forbidden response. This ensures requests to modify the user's billing email originate from the application itself, not from cross-site forgery attacks.

## Behaviour changes
- Clients sending POST requests without a CSRF token will now receive a 403 Forbidden response instead of a 200 OK.
- Legitimate requests from the application's own forms or AJAX calls must include a valid CSRF token to succeed.
- Django's `CsrfViewMiddleware` must be enabled in the `MIDDLEWARE` setting (default in modern Django projects). If it is not present, the view will process requests without token validation; ensure it is listed.
- The `csrf_exempt` import from `django.views.decorators.csrf` is no longer used and can be removed if not used elsewhere.
