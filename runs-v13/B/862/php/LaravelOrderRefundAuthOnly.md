## Verdict

Exploitable. The route enforces authentication via `auth:sanctum` middleware, confirming the caller is logged in, but the controller method performs a sensitive action (order refund) without verifying the authenticated user owns the order. An authenticated user can refund any order by changing the ID in the URL path.

## Source

HTTP request parameter `order` (ID in URL path `/orders/{order}/refund`)

Reaches the sink via Laravel's route model binding, which resolves `{order}` to an Order instance without ownership filtering.

## Fix

**Vulnerable code (routes_api.php, line 6-7):**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum');
```

**Fixed code (routes_api.php, line 6-7):**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum')
    ->middleware('can:refund,order');
```

**Vulnerable code (OrderRefundController.php, line 9-14):**
```php
public function store(Order $order): array
{
    $order->refund();

    return ['status' => 'refunded'];
}
```

**Fixed code (OrderRefundController.php, line 9-14):**
```php
public function store(Order $order): array
{
    Gate::authorize('refund', $order);
    $order->refund();

    return ['status' => 'refunded'];
}
```

**Additional setup required:**

Create or update OrderPolicy (run `php artisan make:policy OrderPolicy --model=Order` if not present):
```php
public function refund(User $user, Order $order): bool
{
    return $user->id === $order->user_id;
}
```

Register the policy in AppServiceProvider::boot() (Laravel 10 and earlier with AuthServiceProvider, or manually if using Laravel 11):
```php
Gate::policy(Order::class, OrderPolicy::class);
```

## Explanation

The fix adds two authorization checks: a route-level `can:refund,order` middleware that delegates to the OrderPolicy, and an explicit `Gate::authorize()` call in the controller method as defense-in-depth. The Policy's `refund()` method compares the authenticated user's ID against the order's `user_id`, ensuring only the order owner can refund it. The route middleware prevents the action from reaching the controller at all if authorization fails, and the controller-level gate provides an additional enforcement point and makes the authorization requirement explicit in the code. Both checks answer 403 (Forbidden) if the caller lacks permission.

## Behaviour changes

None. The fix preserves the original method signature, return type, and behavior for authorized callers. Only unauthorized requests are affected, changing from a successful 200 response to a 403 Forbidden response. The `order` parameter still reaches the controller via route model binding and still answers 404 if the order ID does not exist. Requests from unauthenticated users continue to be rejected by `auth:sanctum` before reaching this route.
