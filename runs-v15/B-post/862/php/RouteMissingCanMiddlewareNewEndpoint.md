## Verdict

Exploitable. The `DELETE /orders/{order}/purge` route performs a sensitive operation (permanent deletion of an order and its line items) with only authentication (`auth:sanctum`) but no authorization check. Any logged-in user can delete any order regardless of ownership or permission.

## Source

Authenticated user making a request to the route (verified by `auth:sanctum` middleware only).

## Fix

**Vulnerable code (line 24):**
```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
```

**Fixed code:**
```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:update,order']);
```

## Explanation

The fix adds the `can:update,order` middleware to the route, enforcing authorization alongside authentication. This middleware checks via Laravel's authorization gate system whether the authenticated user has permission to perform the `update` action on the specific `order` resource (resolved by route model binding). The `order` parameter binds to the Order model instance, and the `can` middleware resolves to an `OrderPolicy` class method or a gate defined via `Gate::define()`, which will verify the user owns the order or holds the required role. This matches the authorization pattern already applied to the sibling `PUT` (update) and `POST` (cancel) routes on the same resource, ensuring consistent authorization across all mutating operations.

## Behaviour changes

None. The middleware chain addition does not alter the route's arguments, return value, or response format. The request handling now enforces authorization before reaching the controller action, preventing unauthorized access. If an unauthorized user calls this endpoint, Laravel's authorization layer will throw `AuthorizationException`, which the framework converts to a 403 Forbidden response by default.
