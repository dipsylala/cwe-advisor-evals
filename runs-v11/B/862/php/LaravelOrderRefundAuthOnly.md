## Verdict

Exploitable

## Source

Authenticated user from `auth:sanctum` middleware, passed as `$order` parameter via route model binding

## Fix

**Vulnerable Code (routes_api.php, line 6):**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum');
```

**Vulnerable Code (OrderRefundController.php, lines 9-14):**
```php
public function store(Order $order): array
{
    $order->refund();

    return ['status' => 'refunded'];
}
```

**Fixed Code (routes_api.php, line 6) - Approach 1: can middleware:**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum')
    ->middleware('can:update,order');
```

**Fixed Code (OrderRefundController.php) - Approach 2: Gate::authorize() in controller:**
```php
public function store(Order $order): array
{
    Gate::authorize('update', $order);

    $order->refund();

    return ['status' => 'refunded'];
}
```

**Required Policy Definition:**
Either fix above requires an OrderPolicy with an `update` method:
```php
public function update(User $user, Order $order): bool
{
    return $user->id === $order->user_id;
}
```

## Explanation

The vulnerability exists because the route requires only `auth:sanctum` middleware, which verifies the user is authenticated, but performs no authorization check to confirm the user is permitted to refund the specific order. This allows any authenticated user to refund any order in the system. The fix adds an authorization layer by either attaching `->middleware('can:update,order')` to the route (making the check visible at the route level) or calling `Gate::authorize('update', $order)` in the controller action. Both approaches delegate authorization to an OrderPolicy that verifies the authenticated user is the owner of the order before the refund executes. The `can:update,order` middleware approach is preferred because authorization is declared explicitly in the route definition and cannot be accidentally omitted from a handler.

## Behaviour changes

- Route now enforces both authentication and authorization: unauthenticated requests return 401, authenticated users without permission return 403
- Refund operation only executes if the authenticated user is the owner of the order
- Unauthorized requests never reach the controller method (when using `can` middleware) or return 403 before executing the refund (when using Gate::authorize in the controller)
- Requires OrderPolicy to be registered via `Gate::policy(Order::class, OrderPolicy::class)` in AppServiceProvider or via auto-discovery (Laravel 11+)
