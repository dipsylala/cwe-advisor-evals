## Verdict

This is a confirmed CSRF vulnerability. The view exempts itself from CSRF protection on a state-changing endpoint that processes user input, allowing an attacker to forge requests that change a user's billing email without their consent.

## Source

`evals/cases/352/python/DjangoExemptBillingEmail/views.py`, line 7: The `@csrf_exempt` decorator disables CSRF protection on the `update_billing_email` view.

The view is a POST endpoint (line 9) that accepts user input via `request.POST.get("email", "")` (line 14) and performs a state-changing operation by calling `BillingMailer.queue_change(request.user.id, email)` (line 15).

## Fix

Remove the `@csrf_exempt` decorator from line 7. The corrected code is:

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

The import statement on line 2 (`from django.views.decorators.csrf import csrf_exempt`) can also be removed as it is no longer used.

## Explanation

Django's CSRF protection is enabled by default through the `CsrfViewMiddleware`, which validates a CSRF token on state-changing requests (POST, PUT, DELETE, PATCH). Applying `@csrf_exempt` disables this validation for the decorated view.

This endpoint qualifies for CSRF protection because it:
1. Uses POST to modify server state (queues an email change)
2. Accepts user-supplied input (the email parameter)
3. Performs the operation based solely on authentication, without requiring an additional authorization token

An attacker can exploit this by embedding a form submission in a malicious web page. When an authenticated user visits that page, their browser automatically sends a POST request with their session credentials, changing their billing email without their knowledge.

Removing `@csrf_exempt` restores Django's default CSRF protection. The middleware will require a valid CSRF token from the request, which can be supplied via the form's `{% csrf_token %}` template tag or as a custom header. This ensures that only requests originating from the application itself (or explicitly authorized callers with access to the token) can successfully change a user's billing email.
