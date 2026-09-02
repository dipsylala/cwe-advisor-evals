## Verdict

Confirmed. The `@csrf_exempt` decorator on line 7 disables CSRF protection for a state-changing endpoint, allowing attackers to forge email-change requests on behalf of authenticated users.

## Source

Line 7: `@csrf_exempt` decorator disables CSRF token validation for the `update_billing_email` view.

## Fix

Remove the `@csrf_exempt` decorator entirely. For JSON/AJAX clients, pass the CSRF token in the `X-CSRFToken` request header (Django's `CsrfViewMiddleware` will validate it automatically).

**Vulnerable code:**
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

**Client-side requirement (for AJAX):**

When calling this endpoint from JavaScript, include the CSRF token in the request header:
```javascript
fetch('/update-billing-email/', {
    method: 'POST',
    headers: {
        'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
    },
    body: new FormData(form)
});
```

## Explanation

The `@csrf_exempt` decorator disables Django's CSRF protection entirely for this endpoint. Removing it allows `CsrfViewMiddleware` (which must be enabled in `MIDDLEWARE` settings) to validate that the request originates from the application itself by requiring a cryptographically random token bound to the user's session. Without this check, an attacker can trick an authenticated user into visiting a malicious site that silently changes their billing email to the attacker's address. The framework validates the token automatically on POST requests; for AJAX clients, the token must be passed in the `X-CSRFToken` header where the middleware expects it.

## Behaviour changes

- Requests to `update_billing_email` without a valid CSRF token will return HTTP 403 (Forbidden)
- Legitimate requests must now include the CSRF token (automatically in forms; in `X-CSRFToken` header for AJAX)
- The endpoint will reject state-changing requests that originate from cross-site contexts
