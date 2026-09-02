## Verdict

exploitable (confidence: high)

## Source

The `{order}` route parameter on `POST /orders/{order}/refund` (`routes_api.php:6`), attacker-controlled via the URL and resolved by Laravel route model binding into the `Order $order` argument of `OrderRefundController::store()`. The route requires only `auth:sanctum`, which establishes that the caller is *some* authenticated user - it does not check any relationship between that user and the specific order being referenced.

## Fix

Vulnerable - `routes_api.php`:

```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware('auth:sanctum');
```

Fixed - `routes_api.php`:

```php
Route::post('/orders/{order}/refund', [OrderRefundController::class, 'store'])
    ->middleware(['auth:sanctum', 'can:refund,order']);
```

New - `app/Policies/OrderPolicy.php` (no policy currently exists for `Order`; one must be added for the `can` middleware to have anything to resolve against):

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

`OrderRefundController::store()` itself is unchanged - the `can` middleware runs before the action, so the controller body stays exactly as it is:

```php
public function store(Order $order): array
{
    $order->refund();

    return ['status' => 'refunded'];
}
```

## Explanation

The route relied on `auth:sanctum` alone, which confirms authentication but performs no authorization check, so any logged-in user could refund any order by changing the `{order}` identifier in the URL. The fix adds `can:refund,order` to the route middleware, which Laravel resolves against a `refund` ability on the model's policy; a new `OrderPolicy::refund()` supplies that ability by comparing the authenticated user to the order's owner (`$user->id === $order->user_id`), following the naming convention that lets Laravel auto-discover `App\Policies\OrderPolicy` for `App\Models\Order`. Route model binding already returns a 404 for an id with no matching row, so pairing it with a policy that denies with a plain `false` (rather than `denyAsNotFound()`) means an existing order owned by someone else answers 403 while a nonexistent order answers 404 - both responses confirm the id space is enumerable. Given this is a POST action rather than a GET, and the finding is specifically about the missing authorization check rather than id-enumeration hardening, the fix keeps the boolean form recommended for role/permission-style checks; if the order id itself should not be probeable, `denyAsNotFound()` should be layered on top in a follow-up change.

**Assumption**: `Order` has a `user_id` column identifying its owner. Neither the `Order` model nor a migration was included in the provided call chain, so this follows the standard Laravel foreign-key convention (`{singular_relation}_id`); the actual owning-user column should be confirmed against the model before merging.

## Behaviour changes

- An authenticated user who does not own the referenced order now receives a 403 (`AuthorizationException`, Laravel's default rendering) instead of having the order refunded. This is the intended effect of closing the missing-authorization gap, not incidental.
- An authenticated user requesting their own order is unaffected: the controller logic, its return value (`['status' => 'refunded']`), and the call to `$order->refund()` are unchanged.
- A request for a non-existent order id continues to answer 404, as it did before (unaffected by this fix - it happens during route model binding, prior to the policy check).
- No other change: no altered arguments, no discarded output, no modified return values beyond the new denial path.
