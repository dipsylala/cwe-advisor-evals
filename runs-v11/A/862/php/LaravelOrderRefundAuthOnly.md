## Verdict
The route allows any authenticated user to refund any order by ID, without verifying ownership or authorization. Authentication alone is insufficient; authorization checks must verify the user has permission for the specific resource.

## Source
**routes_api.php (line 6):**
```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum');
```

**OrderRefundController.php (line 9-13):**
The `store()` method receives the `Order` model instance via implicit route model binding but performs no authorization check before calling `$order->refund()`.

## Fix
Add authorization checks in the controller using Laravel's authorization gates or policies:

**OrderRefundController.php:**
```php
<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

final class OrderRefundController
{
    use AuthorizesRequests;

    public function store(Order $order): array
    {
        $this->authorize('refund', $order);
        
        $order->refund();

        return ['status' => 'refunded'];
    }
}
```

**Define an OrderPolicy (app/Policies/OrderPolicy.php):**
```php
<?php

namespace App\Policies;

use App\Models\Order;
use App\Models\User;

class OrderPolicy
{
    public function refund(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}
```

Register the policy in `app/Providers/AuthServiceProvider.php`:
```php
use App\Models\Order;
use App\Policies\OrderPolicy;

protected $policies = [
    Order::class => OrderPolicy::class,
];
```

## Explanation
The vulnerability occurs because authentication (`middleware('auth:sanctum')`) only verifies the user's identity, not their permission to refund a specific order. Any authenticated user could refund another user's order by changing the order ID in the URL.

The fix introduces authorization by:
1. Using the `$this->authorize('refund', $order)` method to gate the operation on a named ability
2. Defining a Laravel policy that explicitly checks whether the requesting user owns the order (compares `user_id` with the authenticated user's ID)
3. Registering the policy in the service provider so the authorization check is enforced

This ensures each user can only refund their own orders, not others'.
