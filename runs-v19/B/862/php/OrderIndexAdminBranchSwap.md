## Verdict

Exploitable. Non-admin authenticated users are returned all orders without authorization, violating the access control requirement that users see only their own records.

## Source

Line 12: `$user = $request->user();` retrieves the authenticated user from the HTTP request. This source is trusted (authentication has occurred) but authorization has not been validated.

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

The vulnerability is an inverted authorization check. The original code checked `if (! $user->isAdmin())` (if NOT admin) and then returned all orders, granting full access to non-admin users. The fix removes the negation operator `!` to correctly gate access: admin users now receive all orders via `Order::all()`, while non-admin users receive only their own records via the scoped query `Order::where('user_id', $user->id)->get()`. This follows the Laravel authorization pattern described in the guidance: performing an explicit role check before sensitive operations and limiting data access to authenticated users' own resources. The authorization now correctly enforces that only admins see all orders, and regular users see only their own.

## Behaviour changes

The authorization logic is inverted, changing which users receive which dataset:
- Admin users now return all orders (previously returned only their own)
- Non-admin users now return only their own orders (previously returned all)

This is the intended corrective behaviour to close the missing authorization vulnerability. The method still returns an iterable collection in both branches, preserving the return type contract. No parameters, API signatures, or other code contracts have changed beyond the authorization gate itself.
