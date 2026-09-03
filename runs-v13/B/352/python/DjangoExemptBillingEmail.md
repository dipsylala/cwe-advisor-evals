## Verdict

Exploitable. The `@csrf_exempt` decorator on line 7 disables CSRF token validation for a state-changing endpoint (POST request that modifies billing email). An attacker can craft a malicious webpage that, when visited by an authenticated user, POSTs to this endpoint to change the user's billing email without authorization.

## Source

Attacker-controlled webpage that submits a form to `POST /update_billing_email` while a victim user is authenticated to the application. The attacker can control the `email` parameter sent in the POST body.

## Fix

**Vulnerable code:**
```python
from django.views.decorators.csrf import csrf_exempt

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

The `@csrf_exempt` decorator bypasses Django's `CsrfViewMiddleware`, allowing state-changing POST requests to execute without CSRF token validation. Removing the decorator re-enables automatic token validation by the middleware. Django's middleware is configured by default in most projects and validates CSRF tokens on all state-changing methods (POST, PUT, DELETE, PATCH) unless explicitly exempted. The endpoint already checks `request.user.is_authenticated`, so authentication is enforced; removing the exemption ensures that both authentication and CSRF token validation are required before processing billing email changes.

## Behaviour changes

None. Django's `CsrfViewMiddleware` is enabled by default in the `MIDDLEWARE` setting and will automatically validate CSRF tokens on POST requests without any additional code changes to the view. Client-side code (forms and AJAX handlers) must include the CSRF token via the `{% csrf_token %}` template tag or the `X-CSRFToken` header, but this is standard Django CSRF protection and does not change the endpoint's behavior—it only requires callers to be legitimate application code rather than arbitrary cross-site requests.
