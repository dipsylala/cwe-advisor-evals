"""URL routes for the account dashboard app."""

from django.urls import path

from . import views

urlpatterns = [
    path("account/settings/", views.account_settings, name="account_settings"),
    # No require_POST/require_http_methods restriction: GET, POST, or any
    # other verb reaches delete_account() and triggers the account deletion.
    path("account/delete/", views.delete_account, name="delete_account"),
    path("account/orders/", views.account_orders, name="account_orders"),
]
