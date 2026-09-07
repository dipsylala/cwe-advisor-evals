## Verdict

Exploitable. The `@csrf_exempt` decorator on line 7 explicitly disables Django's CSRF protection on a state-changing POST endpoint that modifies user account data (billing email). An attacker can craft a malicious request that exploits an authenticated victim's session to queue unauthorized email changes.

## Source

Attacker-controlled web page (via cross-site form submission) targeting the endpoint at any authenticated user's browser.

## Fix

**Vulnerable code:**
```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from billing_mailer import BillingMailer


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

**Fixed code:**
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

Removing the `@csrf_exempt` decorator restores Django's automatic CSRF token validation. When `CsrfViewMiddleware` is enabled in the project's `MIDDLEWARE` setting (standard in modern Django), Django will require the request to include a valid CSRF token—either in the POST data as `csrfmiddlewaretoken`, in a custom header like `X-CSRFToken`, or in the request body. Requests from malicious sites lacking this token will be rejected with a 403 Forbidden response, preventing forged email-change requests. The endpoint continues to require user authentication, but now adds cryptographic proof that the request originated from the application itself.

## Behaviour changes

None. The fix preserves the endpoint's existing contract: authenticated users can still update their billing email by submitting valid requests with CSRF tokens. Unauthenticated users receive a 401 response, and non-POST requests receive a 405 response. The only change is that requests missing a valid CSRF token are now rejected, which is the correct security behaviour and not a breaking change for legitimate clients that follow the POST pattern.
