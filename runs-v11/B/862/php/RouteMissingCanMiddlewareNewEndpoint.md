## Verdict

Exploitable. The route allows any authenticated user to delete any order without verifying ownership or explicit permission.

## Source

The `{order}` route parameter, which is untrusted with respect to authorization. While the route model binding resolves it to an Order model instance, there is no check confirming the authenticated caller owns or has permission to act on that specific order.

## Fix

Vulnerable code (lines 24–25):
```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
```

Fixed code:
```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:update,order']);
```

## Explanation

The route definition on line 24–25 verifies the caller is authenticated via `auth:sanctum` middleware but provides no authorization check on the specific order resource. The fix adds the `can:update,order` middleware, which invokes the Order Policy's `update` method to verify the authenticated user owns or has permission to act on the order before the controller action executes. This matches the authorization pattern already used on the PUT (line 14) and POST (line 17) routes for the same resource. The Policy method is expected to compare the authenticated user against the resource—for example, `$user->id === $order->user_id`—so only the resource owner can purge it. Laravel converts an authorization failure to a 403 response automatically.

## Behaviour changes

The middleware parameter changes from a string (`'auth:sanctum'`) to an array (`['auth:sanctum', 'can:update,order']`). This is the correct Laravel pattern for applying multiple middleware in sequence and introduces no functional change beyond enforcing the authorization check. The authorization check will reject requests from authenticated users who do not own the order, changing the response from 200 to 403 for unauthorized callers.
