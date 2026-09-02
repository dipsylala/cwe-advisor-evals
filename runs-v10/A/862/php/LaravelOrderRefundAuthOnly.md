## Verdict

**CONFIRMED** — The route requires authentication but lacks authorization. Any authenticated user can refund any order, not just orders they own.

## Source

**File:** `routes_api.php`, line 6  
**Issue:** The route applies `middleware('auth:sanctum')` for authentication but performs no authorization check.

**Call chain:**
1. `routes_api.php` — Route handler with authentication middleware only
2. `OrderRefundController::store()` — Accepts an order but never checks if the current user owns it

The vulnerability: `auth:sanctum` middleware confirms *who* the user is, but the controller never confirms the user is *authorized* to refund this specific order. An attacker can POST `/orders/{any-id}/refund` and refund another customer's order.

## Fix

**Updated OrderRefundController.php:**

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

**Add order policy (app/Policies/OrderPolicy.php):**

```php
<?php

namespace App\Policies;

use App\Models\Order;
use App\Models\User;

class OrderPolicy
{
    public function refund(User $user, Order $order): bool
    {
        return $order->user_id === $user->id;
    }
}
```

**Register policy in AuthServiceProvider.php:**

```php
protected $policies = [
    Order::class => OrderPolicy::class,
];
```

**Alternative (inline check without policy):**

```php
public function store(Order $order): array
{
    if ($order->user_id !== auth()->id()) {
        abort(403, 'Not authorized to refund this order');
    }
    
    $order->refund();

    return ['status' => 'refunded'];
}
```

## Explanation

Authentication (`auth:sanctum`) only verifies the user's identity. Authorization ensures the authenticated user has permission to perform the requested action.

The route handler must verify the user owns the order before allowing the refund. The fix adds an authorization check that compares the authenticated user's ID with the order's owner, preventing unauthorized refunds.

Using Laravel's policy system (first approach) is the framework convention and scales well across multiple authorization rules. The inline check (second approach) works but is less maintainable across multiple methods that need the same ownership validation.

