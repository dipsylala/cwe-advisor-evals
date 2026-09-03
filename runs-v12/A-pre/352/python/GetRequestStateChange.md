## Verdict
Real: Cross-Site Request Forgery (CWE-352)

## Source
The `delete_account` view accepts GET requests and performs a state-changing operation (user deletion) without CSRF protection. An attacker can craft a URL and trick a logged-in user into visiting it (via a link or embedded image), causing their account to be deleted silently.

## Fix
```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import csrf_protect


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_account(request):
    """Permanently delete the signed-in user's account.
    
    Requires a POST request with a valid CSRF token to prevent
    cross-site request forgery attacks.
    """
    user = request.user
    user.delete()
    return redirect("login")
```

The template should render a form with a POST method and CSRF token:
```html
<form method="post" action="/account/delete/">
    {% csrf_token %}
    <button type="submit">Delete Account</button>
</form>
```

## Explanation
The vulnerability occurs because state-changing operations must never use GET requests; GET is cacheable, can be triggered by prefetch, and allows cross-origin triggers. Django provides `@require_http_methods(["POST"])` to restrict the view to POST only, preventing accidental GET invocation. The `@csrf_protect` decorator adds CSRF token validation, requiring attackers to possess the token before the deletion proceeds—a token an attacker cannot obtain from a cross-origin request due to the same-origin policy. The template's `{% csrf_token %}` tag embeds the token in the form, making legitimate requests include it while forged requests from other sites cannot.
