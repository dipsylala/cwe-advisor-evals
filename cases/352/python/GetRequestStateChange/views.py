"""Account management views for the user dashboard app."""

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render


@login_required
def account_settings(request):
    """Render the account settings page with a 'Delete account' link."""
    return render(request, "account/settings.html", {"user": request.user})


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


@login_required
def account_orders(request):
    """Read-only order history, unaffected by this finding."""
    orders = request.user.orders.order_by("-created_at")
    return render(request, "account/orders.html", {"orders": orders})
