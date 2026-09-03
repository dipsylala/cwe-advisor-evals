## Verdict

Exploitable. The route performs a sensitive destructive action (purging an order with cascading deletions) but applies only authentication middleware, not authorization middleware. Any authenticated user can purge any order by identifier.

## Source

HTTP request to `DELETE /orders/{order}/purge` from an authenticated user (via `auth:sanctum`).

## Sink

`Route::delete()` call at line 24, which registers the endpoint without checking whether the authenticated caller has permission to purge the specified order.

## Fix

**Vulnerable code:**
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

The delete route is missing the `can:update,order` authorization middleware that guards comparable mutating routes in the same file (update at line 13–14, cancel at line 16–17). The `can` middleware enforces a Policy check that verifies the authenticated user owns or has permission to act on the specific order instance being purged, not just that they are logged in. Without this check, any authenticated user can guess an order identifier and purge orders belonging to other users. Adding the same `can:update,order` middleware present on the similar routes closes the authorization gap and applies the framework's centralized Policy layer to this endpoint as well.

## Behaviour changes

None. The fix adds an explicit authorization check via the Laravel Policy layer but does not alter the endpoint's response, arguments, return value, or contract for authorized users who hold the required permission. Unauthorized requests receive a 404 response (via `denyAsNotFound`) when scoped through the Policy, which is consistent with the expected behaviour for a user attempting to access a record they do not own.
