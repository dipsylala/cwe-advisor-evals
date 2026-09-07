## Verdict

Exploitable. The authorization check is present but its result is discarded, allowing any authenticated user to update any order.

## Source

Request method: PUT /orders/{order} (authenticated user via `auth` middleware). Route parameter `$order` (Order model instance resolved by route model binding). Request input `shipping_address` and `status` from form validation. Attacker: an authenticated user attempting to update an order that is not theirs.

## Fix

### File: OrderController.php

```php
<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class OrderController extends Controller
{
    /**
     * Update the shipping address and status of an existing order.
     *
     * Route: PUT /orders/{order}  (middleware: auth)
     */
    public function update(Request $request, Order $order)
    {
        $validated = $request->validate([
            'shipping_address' => 'required|string|max:255',
            'status' => 'required|in:pending,processing,shipped,cancelled',
        ]);

        Gate::authorize('update', $order);

        $order->shipping_address = $validated['shipping_address'];
        $order->status = $validated['status'];
        $order->save();

        return response()->json([
            'message' => 'Order updated successfully',
            'order' => $order,
        ]);
    }
}
```

## Explanation

Line 24 is changed from `Gate::allows('update', $order)` to `Gate::authorize('update', $order)`. The original code calls `Gate::allows()` which returns a boolean, but never acts on that result, so execution continues and the order is modified regardless of whether the user is authorized to do so. The fixed code calls `Gate::authorize()` instead, which throws an `Illuminate\Auth\Access\AuthorizationException` if the check fails. Laravel's exception handler catches this and returns a 403 Forbidden response to the client, preventing the unauthorized modification. An authorized user passes the check and execution continues normally.

## Behaviour changes

None. `Gate::authorize()` takes the same arguments as `Gate::allows()` and succeeds silently for an authorized user, producing identical behavior to the original when authorization passes. The only difference is that unauthorized requests now receive a 403 Forbidden response instead of allowing modification.
