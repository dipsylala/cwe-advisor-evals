## Verdict

Confirmed. `OrderController::index()` has the authorization branches reversed: a non-admin user (the `! $user->isAdmin()` branch) is served `Order::all()` — every order in the system, regardless of owner — while the branch reachable only by admins is restricted to the caller's own orders. Any authenticated non-admin user can enumerate all orders belonging to every other user.

## Source

`$request->user()` (the authenticated user resolved by Laravel's auth middleware) is the actor whose role (`$user->isAdmin()`) should gate the scope of the query. Line 16 (`Order::all()`) is the sink: it is reached exactly when the actor is *not* an admin, which is backwards from the intended access control.

## Fix

### File: OrderController.php
```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Order;

final class OrderController
{
    public function index(Request $request): iterable
    {
        $user = $request->user();

        if ($user->isAdmin()) {
            return Order::all();
        }

        return Order::where('user_id', $user->id)->get();
    }
}
```

## Explanation

The only change is the condition guarding the two return statements: `if ($user->isAdmin())` now selects the unrestricted `Order::all()` query, and the `else` path (falling through to the final `return`) restricts non-admins to `Order::where('user_id', $user->id)->get()`. This preserves the original intent — admins can see every order, ordinary users can see only their own — while closing the missing-authorization gap where a non-admin previously received the unrestricted result set. No other logic, signature, or return type was changed, so callers are unaffected except that non-admins now correctly receive only their own orders.
