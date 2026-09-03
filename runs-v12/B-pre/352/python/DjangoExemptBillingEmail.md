## Verdict

Exploitable. The `@csrf_exempt` decorator on line 7 disables CSRF protection for an authenticated state-changing endpoint, allowing attackers to forge requests from malicious sites to modify the user's billing email.

## Source

HTTP POST request with attacker-controlled `email` parameter, forged by malicious site when the user is authenticated to the application.

## Fix

Remove the `@csrf_exempt` decorator from line 7. Django's `CsrfViewMiddleware` (configured by default in Django) will then validate CSRF tokens for all state-changing POST requests.

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

For AJAX requests, the client must include the CSRF token in the `X-CSRFToken` header. For form-based submissions, include `{% csrf_token %}` in the HTML form.

## Explanation

The `@csrf_exempt` decorator explicitly disables Django's CSRF protection for this view. Since the endpoint performs a state-changing operation (modifying user billing email) on an authenticated user's account, it is a high-value target for CSRF attacks. An attacker can host a malicious page that makes a forged POST request to this endpoint; if the user visits that page while authenticated, the browser automatically sends the user's session cookie, and the exemption allows the request to proceed without token validation. Removing the decorator re-enables the default CSRF token validation, ensuring that only requests originating from the application itself (which can obtain and send the CSRF token) are accepted.

## Behaviour changes

None. The endpoint's response contract remains unchanged. Django's middleware automatically validates tokens for POST requests without modifying the view's logic or return values. Legitimate requests (including AJAX and form submissions) that provide the CSRF token will continue to work. Only forged requests lacking the valid token will be rejected with a 403 Forbidden response.
