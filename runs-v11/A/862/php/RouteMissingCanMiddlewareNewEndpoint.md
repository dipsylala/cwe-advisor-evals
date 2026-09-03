## Verdict

Missing authorization check on DELETE /orders/{order}/purge endpoint. The route enforces authentication but not authorization - any logged-in user can purge any order.

## Source

File: routes_orders.php, lines 24-25

```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
```

The route has `auth:sanctum` (authentication) but lacks the `can:...` authorization middleware that its sensitivity level requires. The comments above explicitly state the purge operation is "at least as sensitive as update," which uses `can:update,order`.

## Fix

Add authorization middleware to verify the user has permission to act on the specific order:

```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:purge,order']);
```

If purging requires the same permission as updating, use `can:update,order` instead of `can:purge,order` to reuse the existing policy.

## Explanation

The vulnerability allows authorization bypass: authentication confirms the caller is logged in, but authorization must verify the caller is permitted to act on this *specific* order. Laravel's `can:` middleware enforces model policies - `can:purge,order` will invoke the Order policy's `purge()` method to check ownership or role-based access.

Without this middleware, the route treats all authenticated users as having equal access to all orders, violating the principle that sensitive operations (data deletion) require explicit per-resource authorization checks. The existing update and cancel routes follow the correct pattern; the purge route must match it.
