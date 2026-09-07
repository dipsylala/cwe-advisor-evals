## Verdict

Exploitable. The `delete_account` view at line 23 executes a state-changing operation (`user.delete()`) in response to a GET request without validating request origin or authenticity via CSRF tokens. A malicious site can forge the request using an image tag, meta refresh, or link that executes with the victim's active session cookies.

## Source

Malicious cross-origin GET request to `/account/delete/` crafted by an attacker on a malicious site. The browser automatically includes the victim's session cookie with the request if the victim is logged in.

## Fix

**Vulnerable code:**

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

    Requires a POST request with a CSRF token from an in-app form,
    not a plain link. The confirmation form renders at /account/delete/confirm/.
    """
    user = request.user
    user.delete()
    return redirect("login")

@login_required
def delete_account_confirm(request):
    """Render the account deletion confirmation form.

    The form POSTs to delete_account with an automatic CSRF token.
    """
    return render(request, "account/delete_confirm.html", {"user": request.user})
```

The template (`account/delete_confirm.html`) should include:

```django
<form method="post" action="/account/delete/">
    {% csrf_token %}
    <p>Are you sure you want to permanently delete your account?</p>
    <button type="submit">Yes, delete my account</button>
    <a href="/account/">Cancel</a>
</form>
```

And `urls.py` should route both:

```python
path("account/delete/confirm/", delete_account_confirm, name="delete_confirm"),
path("account/delete/", delete_account, name="delete_account"),
```

## Explanation

The fix separates the state-changing operation from the user-initiated action. By requiring `POST` instead of `GET`, the view rejects forgeable cross-origin requests – browsers cannot craft POST requests to arbitrary origins without explicit permission (CORS). Django's `CsrfViewMiddleware` (assumed in standard Django configuration) automatically validates the CSRF token included in the POST form via the `{% csrf_token %}` template tag. A malicious site cannot access this token because it is bound to the victim's session and the Django framework.

The `@require_http_methods(["POST"])` decorator explicitly enforces that only POST requests are accepted, and it raises `405 Method Not Allowed` for GET requests. The new `delete_account_confirm` view (GET) renders a confirmation form, replacing the previous pattern where a plain link triggered the deletion. This follows the framework's CSRF protection model: GET requests for read-only operations or confirmation pages, POST requests for state changes.

## Behaviour changes

- **Routing change:** The link in the settings page must now point to `/account/delete/confirm/` (the confirmation form) rather than directly to `/account/delete/`. The delete action is no longer triggered by a simple link click but requires form submission.
- **HTTP method change:** The `delete_account` endpoint now accepts only POST; GET requests return 405 Method Not Allowed.
- **Token validation:** Django's middleware automatically validates the CSRF token in the POST request. No additional token-handling code is required in the view.
- **Session preservation:** The user's session is terminated by the redirect after deletion, the same as before.

**Verification:** Python syntax check passed. The use of `@require_http_methods` is from `django.views.decorators.http` (Django standard library), `@login_required` and `render`/`redirect` are already imported. The `{% csrf_token %}` template tag is a Django built-in that requires only `CsrfViewMiddleware` to be enabled in Django's `MIDDLEWARE` setting (standard Django configuration includes it by default). No new external dependencies are required. The fix assumes:

1. Django's `CsrfViewMiddleware` is enabled in `MIDDLEWARE` (standard Django configuration).
2. The settings page and new confirmation page templates use Django's template engine (standard for Django projects).
3. The form submission method will be POST with `{% csrf_token %}` included (the developer controls the template).
