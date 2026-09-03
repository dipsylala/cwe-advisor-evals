## Verdict

Exploitable. The `@csrf_exempt` decorator at line 7 explicitly disables Django's CSRF protection on a state-changing endpoint, allowing attackers to forge authenticated POST requests that modify user data without the user's knowledge or consent.

## Source

The vulnerability exists in `evals/cases/352/python/DjangoExemptBillingEmail/views.py` at line 7, where the `@csrf_exempt` decorator removes CSRF token validation from the `update_billing_email` endpoint. User-controlled input from `request.POST.get("email", "")` reaches the vulnerable sink (the unprotected handler) with no CSRF token validation.

## Fix

Remove the `@csrf_exempt` decorator. Django's built-in `CsrfViewMiddleware` will automatically validate CSRF tokens for all POST requests.

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

## Explanation

The `@csrf_exempt` decorator explicitly disables Django's CSRF protection mechanism for this endpoint. Removing it restores automatic CSRF token validation via Django's `CsrfViewMiddleware` (included in Django's default middleware stack). The middleware will validate that POST requests include a valid CSRF token from either form data or the `X-CSRFToken` header before allowing execution. This prevents attackers from forging authenticated requests to change a user's billing email, closing the CSRF vulnerability.

## Behaviour changes

None. Removing the decorator simply restores Django's standard CSRF protection that is enabled by default. Legitimate requests submitted via Django forms (which include `{% csrf_token %}`) or AJAX requests (which include the token in the `X-CSRFToken` header) will function identically. Only forged cross-site requests lacking a valid CSRF token will be rejected with a 403 Forbidden response by the middleware.
