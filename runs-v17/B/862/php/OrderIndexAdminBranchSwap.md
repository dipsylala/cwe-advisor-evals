## Verdict

Exploitable. The authorization check at line 14 contains a logic error: the condition `if (! $user->isAdmin())` is inverted, causing non-admin authenticated users to receive all orders globally instead of being restricted to their own. The fix negates the condition to enforce the correct authorization logic.

## Source

`$user = $request->user()` (line 12) - the authenticated user. The user object is queried for its role via `isAdmin()` to determine whether to return all orders or only the user's own.

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

The original condition `if (! $user->isAdmin())` was inverted, causing the authorization logic to operate backwards: non-admin users received all orders via `Order::all()`, while admin users received only their own orders. The fix removes the negation operator (`!`) so that `if ($user->isAdmin())` correctly grants all-orders access only to admin users. Non-admin users now receive only their own orders via the filtered query on line 19. This enforces the intended role-based authorization: global data visibility is restricted to administrators, while regular authenticated users see only records they own.

## Behaviour changes

None. The fix corrects the authorization logic to the intended behavior without altering return types, method signatures, or the queries themselves. Both code paths continue to return `iterable` as declared, and the data filtering mechanism remains unchanged—only the condition determining which path executes is corrected.
