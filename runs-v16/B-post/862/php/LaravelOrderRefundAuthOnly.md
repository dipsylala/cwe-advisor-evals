## Verdict

exploitable

## Source

The `{order}` parameter in the HTTP POST request to `/orders/{order}/refund` carries a guessable order ID supplied by the client.

## Fix

**Vulnerable code (routes_api.php, line 6):**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum');
```

**Fixed code:**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum')
    ->middleware('can:update,order');
```

The controller method remains unchanged.

To support this fix, define an Order Policy with an `update` method that verifies ownership:

```php
// app/Policies/OrderPolicy.php
public function update(User $user, Order $order): bool
{
    return $user->id === $order->user_id;
}
```

Register the Policy in `AppServiceProvider::boot()` (Laravel 10 and earlier) or rely on auto-discovery (Laravel 11+).

## Explanation

The original route only verifies authentication via `auth:sanctum`, confirming the caller is logged in. It performs no authorization check on the specific order being refunded. An authenticated attacker can refund orders they do not own by guessing or enumerating order IDs.

The fix adds the `can:update,order` middleware, which invokes the Order Policy's `update` method before the request reaches the controller. The Policy method compares the authenticated user's ID against the order's owner ID. If the check fails, Laravel returns a 404 response (matching the "does not exist" response for non-existent orders, preventing enumeration of order IDs). Route model binding already injects the resolved Order instance into the middleware, so `order` is available as the policy method's second parameter.

## Behaviour changes

The route will now reject requests where the authenticated user does not own the order with a 404 response. Previously, all requests from any authenticated user succeeded. No other behaviour changes; the controller method, response structure, and successful refund logic remain identical.
