## Verdict

Exploitable. A GET request performs an authenticated state-changing operation (account deletion) without CSRF token validation. Django's CSRF middleware validates only non-safe methods (POST, PUT, DELETE), so GET requests bypass protection entirely. An attacker can exploit this by tricking an authenticated user into clicking a link on a malicious site, causing the user's account to be deleted without their knowledge.

## Source

**Location**: evals/cases/352/python/GetRequestStateChange/views.py, line 23

**Source**: The authenticated user's HTTP GET request, implicitly trusted by `@login_required` decorator.

**Sink**: `user.delete()` at line 23. This state-changing operation is reachable directly from a GET request with no CSRF token requirement.

## Fix

**Vulnerable code**:
```python
@login_required
def delete_account(request):
    """Permanently delete the signed-in user's account.

    Linked from the settings page as a plain <a href="/account/delete/">
    so the browser issues a GET request. urls.py registers this view with
    no method restriction, so GET is what actually reaches it.
    """
    user = request.user
    user.delete()
    return redirect("login")
```

**Fixed code**:
```python
from django.views.decorators.http import require_http_methods

@login_required
@require_http_methods(["GET", "POST"])
def delete_account(request):
    """Permanently delete the signed-in user's account.

    GET renders a confirmation page with a form that POSTs to this endpoint.
    POST with a valid CSRF token deletes the account.
    """
    if request.method == "POST":
        user = request.user
        user.delete()
        return redirect("login")
    
    # GET request - render confirmation page
    return render(request, "account/delete_confirm.html", {"user": request.user})
```

A corresponding form template for `account/delete_confirm.html`:
```html
<form method="post">
    {% csrf_token %}
    <p>Are you sure you want to delete your account? This action cannot be undone.</p>
    <button type="submit">Yes, delete my account</button>
    <a href="{% url 'account_settings' %}">Cancel</a>
</form>
```

## Explanation

The original code accepts GET requests to perform account deletion, bypassing Django's CSRF middleware entirely because the middleware only validates POST, PUT, PATCH, and DELETE methods. The vulnerability allows an attacker to craft a malicious link that, when clicked by an authenticated user, automatically deletes the user's account without their explicit confirmation or knowledge. The fix implements a two-step confirmation pattern: GET requests render a confirmation page with an HTML form that includes a CSRF token via the `{% csrf_token %}` template tag, while only POST requests with a valid CSRF token are accepted to perform the actual deletion. This ensures the state-changing operation is protected by CSRF token validation and requires explicit user intent. The `@require_http_methods(["GET", "POST"])` decorator explicitly restricts the endpoint to these two methods, rejecting others with a 405 response. By keeping the GET endpoint functional (rendering a confirmation page), existing links to the URL continue to work rather than breaking silently, which matches the remediation guidance for CSRF findings where the route was originally accessible via GET for user convenience.

## Behaviour changes

- **GET requests now render a confirmation page** instead of immediately deleting the account. This preserves backward compatibility with existing links (bookmarks, email links) by guiding users to a confirmation form rather than immediately triggering deletion.
- **State-changing operation moved to POST method**. The actual `user.delete()` call now only executes on POST requests with a valid CSRF token, protecting against cross-site request forgery.
- **CSRF token validation is now enforced**. Django's middleware automatically validates the CSRF token present in the POST form data, rejecting requests from cross-origin sources that lack the token.
- **HTTP method restrictions tightened** via `@require_http_methods(["GET", "POST"])`, which rejects PUT, DELETE, PATCH, or other methods with a 405 Method Not Allowed response.
- **Added import**: `require_http_methods` from `django.views.decorators.http`.
