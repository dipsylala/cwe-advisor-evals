## Verdict

Exploitable. The `delete_account` view processes a state-changing operation (account deletion) via GET requests without CSRF token validation. An attacker can craft a simple HTML page with an `<img src="https://victim.com/account/delete/">` tag to force a logged-in victim to delete their account.

## Source

Attacker-crafted HTTP GET request to the `/account/delete/` endpoint, leveraging the victim's active authenticated session.

## Fix

**Vulnerable code (views.py, lines 13-24):**
```python
@login_required
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Linked from the settings page as a plain <a href="/account/delete/">
    so the browser issues a GET request. urls.py registers this view with
    no method restriction, so GET is what actually reaches it.
    """
    user = request.user
    # SAST FINDING: CWE-352 (Cross-Site Request Forgery) reported here. Sink is the next statement.
    user.delete()
    return redirect("login")
```

**Fixed code:**
```python
from django.views.decorators.http import require_http_methods

@login_required
@require_http_methods(["POST"])
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Accessed via POST form with CSRF token validation enforced by
    django.middleware.csrf.CsrfViewMiddleware.
    """
    user = request.user
    user.delete()
    return redirect("login")
```

**Django settings.py** - ensure CSRF middleware is enabled:
```python
MIDDLEWARE = [
    # ... other middleware ...
    'django.middleware.csrf.CsrfViewMiddleware',
    # ... other middleware ...
]
```

**Template (account/settings.html)** - change the delete link to a POST form:
```html
<form method="post" action="/account/delete/">
    {% csrf_token %}
    <button type="submit" class="btn btn-danger">Delete Account</button>
</form>
```

## Explanation

The vulnerability exists because the `delete_account` view accepts GET requests for a state-changing operation (permanent account deletion) without CSRF token validation. According to Django's CSRF protection model, middleware only validates non-safe methods (POST, PUT, DELETE), but only if the endpoint actually requires those methods. A GET endpoint bypasses the protection entirely. An attacker can exploit this by crafting a malicious HTML page containing an image tag or iframe pointing to the victim's delete endpoint—the browser automatically sends the victim's session cookie with the request, causing account deletion without the victim's knowledge or consent. The fix involves three changes: (1) restrict the view to POST-only using `@require_http_methods`, which makes the CSRF middleware protection active; (2) ensure `CsrfViewMiddleware` is in Django's middleware stack; and (3) update the form/template to include the `{% csrf_token %}` tag and use POST instead of a simple link. This prevents attackers from triggering the action via simple cross-site requests.

## Behaviour changes

- The endpoint now requires POST requests instead of GET—any code calling this endpoint as a GET must switch to POST with a form submission
- CSRF token validation is now enforced by middleware—requests without a valid token will be rejected with a 403 Forbidden response
- The template must be updated to include a form with `{% csrf_token %}` and a submit button instead of a plain link
- No changes to the return value or error handling behavior—the redirect to the login page on success remains the same
