## Verdict

Confirmed. The `delete_account` view performs account deletion (a state-changing operation) on a GET request. Django's CSRF protection middleware does not validate tokens on GET requests, leaving this endpoint vulnerable to CSRF attacks.

## Source

Attacker-controlled: the HTTP request itself (method and origin)

Sink: `user.delete()` at line 23, reachable via GET without token validation

Data flow: Unauthenticated attacker crafts a link to `/account/delete/`, tricks authenticated user into clicking it (via email, social media, etc.), user's browser follows the link with active session cookie, GET request reaches the view and deletes the account.

## Fix

**Modified `delete_account` view:**

```python
@login_required
def delete_account(request):
    """Render a confirmation form for account deletion.
    
    GET renders the confirmation page; POST performs the deletion.
    """
    if request.method == 'POST':
        user = request.user
        user.delete()
        return redirect("login")
    
    return render(request, "account/delete_confirm.html")
```

**New confirmation template** (`account/delete_confirm.html`):

```html
{% csrf_token %}
<form method="post" action="{% url 'delete_account' %}">
    {% csrf_token %}
    <p>Are you sure you want to permanently delete your account?</p>
    <button type="submit" name="confirm" value="yes">Yes, delete my account</button>
    <a href="{% url 'account_settings' %}">Cancel</a>
</form>
```

**No changes required to `urls.py`** – the view now explicitly branches on `request.method`, so registering it without method restrictions is safe.

## Explanation

The fix applies the Synchronizer Token Pattern by moving the deletion operation from GET to POST. The GET endpoint now renders a confirmation page containing a form with `{% csrf_token %}`; clicking "confirm" POSTs the form. Django's `CsrfViewMiddleware` validates the token on the POST request before it reaches the view, checking that the token matches the session's CSRF token. An attacker on a malicious site cannot craft a request that includes the user's valid CSRF token (it is bound to the session and not sent to third parties), so the attack fails. The `{% csrf_token %}` template tag automatically injects the current session's token into the form as a hidden field.

The GET endpoint remains accessible from settings pages and email links (preserving existing links), but no longer mutates state – it only renders the confirmation page. This avoids a breaking change while closing the vulnerability.

## Behaviour changes

- **GET requests** to `/account/delete/` now return a confirmation page (HTTP 200 + HTML) instead of deleting the account and redirecting to login.
- **Users** must now click a button on the confirmation page to complete deletion, instead of deletion happening on link click. Existing links to the URL will not delete accounts.
- **POST requests** to `/account/delete/` with a valid CSRF token complete the deletion and redirect to login (new path, requires the confirmation form).
- **CSRF protection** now active: requests without a valid token or from a different origin are rejected (403 Forbidden).
