## Verdict

**exploitable** (confidence: high)

- CWE-862 (Missing Authorization)
- Location: `routes_orders.php`, line 24-25, `Route::delete('/orders/{order}/purge', ...)`

## Source

- **Source**: the `{order}` route parameter in the URL path, supplied by any authenticated caller and resolved by Laravel route model binding into an `Order` model instance passed to `OrderController::purge`.
- **Sink**: the `Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])` registration itself, at line 24. Its `->middleware('auth:sanctum')` call confirms only that the caller is logged in - it does not check that the caller is permitted to purge this specific order.
- **Data flow**: comparing this route to its siblings in the same file shows the gap directly. `PUT /orders/{order}` and `POST /orders/{order}/cancel` both pair `auth:sanctum` with `can:update,order`, which invokes `OrderPolicy::update($user, $order)` (comparing the authenticated user against the order's owner/role) before the controller method runs. The new `DELETE /orders/{order}/purge` route omits the `can:update,order` middleware entirely, so `OrderController::purge` executes for any authenticated user regardless of whether they own or are otherwise entitled to act on that order - the exact pattern the in-file comment at lines 19-22 already flags. This is a missing check, not a flawed one (ruling out CWE-863), and authentication is present (ruling out CWE-306).

## Fix

### File: routes_orders.php

```php
<?php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

// Order management routes. Each mutating route is expected to pair
// auth:sanctum (confirms the caller is logged in) with a can:... check
// (confirms the caller is allowed to act on this specific order).

Route::get('/orders/{order}', [OrderController::class, 'show'])
    ->middleware('auth:sanctum');

Route::put('/orders/{order}', [OrderController::class, 'update'])
    ->middleware(['auth:sanctum', 'can:update,order']);

Route::post('/orders/{order}/cancel', [OrderController::class, 'cancel'])
    ->middleware(['auth:sanctum', 'can:update,order']);

// Purging permanently removes the order and its line items, so it is at
// least as sensitive as update - gated behind the same can:update,order
// check (OrderPolicy::update) used by the other mutating routes above.
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:update,order']);
```

## Explanation

The fix adds the `can:update,order` route middleware to the `purge` route, matching the exact mechanism already applied to the sibling `update` and `cancel` routes on the same resource. Laravel resolves `order` via route model binding before the middleware runs, and `can:update,order` calls the registered `OrderPolicy::update($user, $order)` method, which compares the authenticated user against the order's owner/role, denying with a 403 (`AuthorizationException`) when the check fails. This closes the gap the finding identifies - an authenticated-but-unentitled caller could invoke `purge` on any order by id - without introducing a new permission or ability; it reuses the same ownership/role rule already enforced for `update` and `cancel` on this resource, consistent with the file's own comment that a mutating route should pair `auth:sanctum` with a `can:...` check. No change was made to `OrderController::purge` or to `OrderPolicy` (neither is present in the trace available for this finding); the fix is scoped to wiring the existing centralized authorization check onto the route that was missing it.

**Verification**: `php -l` was run against the fixed file in a scratch location (outside the case directory) and reported no syntax errors. Every name introduced by the fix (`can:update,order` middleware, `Route::delete`) already appears verbatim on the sibling routes in the same file, so no new API, class, or package name was introduced that required independent verification.

**Assumptions**: `OrderController::purge` and the `OrderPolicy` class were not included in the material provided for this finding; the fix assumes `update` is the correct existing ability to reuse for `purge`, based on the in-file comment describing purge as "at least as sensitive as update" and on the fact that the existing `cancel` route already reuses `update` rather than a dedicated ability - i.e., this codebase gates multiple distinct mutating actions on the same resource behind one coarse-grained `update` permission rather than one ability per action. If `OrderPolicy` does not yet define an `update` method, or if purge is intended to require a stricter permission than update (e.g. restricted to support staff specifically, per the comment), that policy method or a new `purge` ability would need to be defined separately - that is a policy-authoring decision beyond the scope of this route-file fix and is called out here rather than invented.

## Behaviour changes

- Added `can:update,order` to the `purge` route's middleware array. Effect: requests to `DELETE /orders/{order}/purge` from an authenticated user who fails `OrderPolicy::update($user, $order)` now receive a 403 (`AuthorizationException`) instead of executing the purge. This is the intended closure of the CWE-862 gap, not an unrelated behavior change.
- No other route, argument, return value, or response body was altered. `show`, `update`, and `cancel` routes are unchanged. The `purge` route's path, controller binding, and HTTP verb are unchanged.
- None of the sink's existing contract (route registration semantics, controller invocation, route-model-binding behavior) was otherwise modified.
