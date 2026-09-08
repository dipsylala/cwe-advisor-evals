## Verdict

exploitable

## Source

`Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])->middleware('auth:sanctum')` in `routes_api.php:5-6` - route-model binding resolves `{order}` into an `Order` model for any authenticated caller, gated only by `auth:sanctum` (authentication, not authorization).

## Fix

### File: OrderRefundController.php

```php
<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Support\Facades\Gate;

final class OrderRefundController
{
    public function store(Order $order): array
    {
        Gate::authorize('refund', $order);

        $order->refund();

        return ['status' => 'refunded'];
    }
}
```

### File: app/Policies/OrderPolicy.php

```php
<?php

namespace App\Policies;

use App\Models\Order;
use App\Models\User;
use Illuminate\Auth\Access\Response;

class OrderPolicy
{
    public function refund(User $user, Order $order): Response
    {
        return $user->id === $order->user_id
            ? Response::allow()
            : Response::denyAsNotFound();
    }
}
```

## Explanation

`OrderRefundController::store()` was reachable by any authenticated user for any order id, because `auth:sanctum` confirms identity only and the handler went straight to `$order->refund()` with no check that the caller owns the order (CWE-862). The fix adds `Gate::authorize('refund', $order)` at the top of the action, which Laravel resolves to a new `OrderPolicy::refund()` method via the framework's default `App\Models\{Model}` -> `App\Policies\{Model}Policy` auto-discovery convention - no explicit `Gate::policy()` registration is needed. The policy method compares the authenticated user's id to the order's `user_id` and denies with `Response::denyAsNotFound()` when they don't match, so a caller probing another user's order id gets the same 404 as a nonexistent id rather than a 403 that would confirm the id is valid. An unauthorized call now throws `AuthorizationException`, which Laravel's exception handler renders as the denied response before `refund()` ever executes.

## Behaviour changes

- Sink contract preserved: on success, `store()` still returns `['status' => 'refunded']` and still calls `$order->refund()` with no argument changes; nothing the original returned or discarded is altered for an authorized caller.
- New behaviour (intentional, closes the weakness): a request for an order the authenticated user does not own now fails with a 404 (via `denyAsNotFound()`) instead of executing the refund. This is the fix, not a side effect.
- Assumption: `Order` has a `user_id` column identifying its owner, following the codebase's standard Laravel convention for user-owned resources - this field isn't visible in the two provided files and could not be confirmed against the model or migrations. If the actual ownership column has a different name, substitute it in the policy's comparison; the rest of the fix (adding a policy-backed `Gate::authorize()` call, deny-as-not-found for a guessable id) is unaffected.
- No other file (including `routes_api.php`) was changed.

## Verification

Ran `php -l` (PHP 8.5.8 CLI) against both fixed files from a scratch copy outside the codebase: `No syntax errors detected` for both `OrderRefundController.php` and `OrderPolicy.php`. All new names were checked against the loaded PHP guidance and Laravel's documented conventions rather than recall: `Gate::authorize()` and `Illuminate\Auth\Access\Response::denyAsNotFound()` are named directly in `cwe/862/php/INDEX.md`; `App\Models\User`, the `App\Policies` namespace, and policy auto-discovery by model-name convention are Laravel's default application skeleton and framework behavior, not third-party additions.
