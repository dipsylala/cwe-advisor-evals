## Verdict

Exploitable.

## Source

Any authenticated user calling the `/orders/{order}/purge` DELETE endpoint with an order ID they do not own.

## Fix

**Vulnerable code (line 24-25):**
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

The route applies `auth:sanctum` middleware, which confirms the caller is logged in, but omits the `can:update,order` middleware that guards comparable sensitive routes (`update` on line 14 and `cancel` on line 17). Without the authorization check, any authenticated user can purge any order, regardless of ownership. The fix adds the `can` middleware to enforce the same resource-level authorization already applied to other mutating operations on the order resource. Laravel resolves the `order` parameter via route model binding and passes it to the Policy method registered for the `Order` model, which compares the authenticated user to the resource's owner before allowing the delete.

## Behaviour changes

None. The `can:update,order` middleware leverages the existing `Order` Policy that is already defined and in use by the `update` and `cancel` routes. No new dependencies, no altered return values, no implicit defaults changed. The middleware aborts with a 403 (or 404 if the Policy uses `denyAsNotFound()`) before the controller action runs, preserving the framework's standard authorization response behavior.

**cwe_id:** 862  
**location:** evals/cases/862/php/RouteMissingCanMiddlewareNewEndpoint/routes_orders.php:24  
**confidence:** high  
**library_recommendation:** none  
**verification:** PHP syntax check passed (`php -l`)  
**assumptions:** Route model binding resolves `{order}` to an `Order` model instance; `Order` Policy with `update` method comparing `$user->id === $order->user_id` is already defined and registered; `auth:sanctum` is a first-party Laravel authentication guard present in the application.
