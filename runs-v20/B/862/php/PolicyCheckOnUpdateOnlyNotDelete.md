## Verdict

exploitable

- cwe_id: CWE-862 (Missing Authorization)
- location: `OrderController.php`, `destroy()`, line 35 (`$order->delete();`)
- confidence: high

## Source

The route parameter `$order` is resolved by Laravel route model binding directly from the request's URL identifier - any authenticated caller can supply an arbitrary order id and receive the corresponding `Order` model instance as the method argument, with no ownership or role check applied before it reaches `destroy()`.

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
    public function show(Order $order)
    {
        Gate::authorize('view', $order);

        return response()->json($order);
    }

    public function update(Request $request, Order $order)
    {
        Gate::authorize('update', $order);

        $validated = $request->validate([
            'shipping_address' => 'sometimes|string|max:255',
            'notes' => 'sometimes|string|max:1000',
        ]);

        $order->update($validated);

        return response()->json($order);
    }

    public function destroy(Order $order)
    {
        Gate::authorize('delete', $order);

        $order->delete();

        return response()->json(null, 204);
    }
}
```

## Explanation

`sink`: `$order->delete()` is the sensitive operation - it permanently removes a specific, bound-by-id `Order` record with no check on the caller's relationship to it. `show()` and `update()` on the same controller both call `Gate::authorize()` against the same `$order` instance before acting, which shows the application already has a registered Policy for the `Order` model that gates per-resource access; `destroy()` is the one action on that resource left uncovered, letting any authenticated user delete any order by id regardless of ownership. The fix adds `Gate::authorize('delete', $order)` as the first statement in `destroy()`, using the identical centralized mechanism (`Gate::authorize()` against the resolved model instance) already used by the sibling methods, rather than an inline ad hoc check. This assumes the existing `OrderPolicy` class (implied by the `view`/`update` calls already present, though not itself in the provided file) defines or is extended with a `delete(User $user, Order $order)` method that compares the authenticated user against the order's owning user, consistent with how `update`/`view` are presumably implemented - this mirrors Laravel's documented convention that a Policy method name matches the ability string passed to `Gate::authorize()`. An unauthorized call now throws `AuthorizationException`, which Laravel's exception handler converts to a 403 response by default, so the `delete` route now denies exactly as `show`/`update` already do for callers who are not permitted to act on that specific order.

## Behaviour changes

- Added `Gate::authorize('delete', $order);` as the first line of `destroy()`. This is the sole change: no arguments, return values, or response bodies were altered on the two other methods or on the success path of `destroy()` itself. On a caller who is not authorized to delete the given order, the endpoint now returns a 403 (via the framework's default `AuthorizationException` handling) instead of performing the deletion and returning 204 - this is the intended closure of the missing-authorization weakness, not an incidental change.
- Assumption: the `OrderPolicy` class exists (implied by the pre-existing `view`/`update` `Gate::authorize()` calls, which would otherwise also fail) and either already defines a `delete` method or needs one added; that class is not part of the provided call chain, so its `delete` method's ownership-comparison logic could not be inspected or verified directly - only the controller-level gap (line 35) was in scope for this fix, consistent with fixing the missing check rather than redesigning the authorization scheme. Confidence is lowered to high-but-not-verified on this one point accordingly.
- Verification: `php -l` was run against the fixed file in a scratch copy outside the case directory - result: "No syntax errors detected". No compiler/framework instance was available to execute the Policy resolution at runtime, so the `Gate::authorize()` call's resolution to an existing `OrderPolicy::delete()` method could not be confirmed beyond the naming-convention inference stated above.
