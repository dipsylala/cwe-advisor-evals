## Verdict

**Real vulnerability confirmed.** The conditional logic at line 16 is inverted, granting non-admin authenticated users access to all orders via `Order::all()` instead of restricting them to their own. This violates the authorization requirement that only admins should retrieve all orders.

## Source

Line 16 in `OrderController.php`: `return Order::all();` executed when `! $user->isAdmin()` is true.

Data flow: The `$user->isAdmin()` check (line 14) gates the operation, but the logic is backwards — a false result (non-admin) reaches the sensitive sink instead of being denied.

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

        if (! $user->isAdmin()) {
            return Order::where('user_id', $user->id)->get();
        }

        return Order::all();
    }
}
```

## Explanation

The fix inverts the conditional logic so that:
- Non-admin users are denied access to `Order::all()` and instead receive only their own orders via `WHERE user_id = ?`
- Admin users receive all orders via `Order::all()`

This applies the authorization principle that sensitive operations require an explicit check: non-admins now fail the admin check and fall through to the scoped query, while admins pass and reach the all-orders endpoint. The `$user->isAdmin()` check now correctly gates access to sensitive data (all orders).

## Behaviour changes

- **Non-admin users**: Previously received all orders; now receive only orders where `user_id` matches their authenticated user ID.
- **Admin users**: Previously received only their own orders; now receive all orders.

Both outcomes now align with the intended access control policy implied by the `isAdmin()` check.
