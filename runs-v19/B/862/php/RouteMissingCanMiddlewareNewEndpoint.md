## Verdict

Exploitable. Any authenticated user can call the purge endpoint on any order without authorization, because the route definition lacks the authorization middleware present on comparable routes (update, cancel).

## Source

Any authenticated user (`auth:sanctum` middleware permits all logged-in callers), accessed via HTTP DELETE to `/orders/{order}/purge`.

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

// New: allow support staff to permanently purge an order once it has been
// refunded and archived. Purging removes the row and its line items, so it
// is at least as sensitive as update - but only auth:sanctum was wired up
// here, so any logged-in user can purge any order by id.
// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:update,order']);
```

## Explanation

The purge route was missing the `can:update,order` authorization middleware present on all comparable state-changing routes (update, cancel). Adding this middleware to the route definition reuses the application's existing authorization layer: the `OrderPolicy` (or equivalent gate definition) that already gates update and cancel operations now gates purge as well. Laravel's `can` middleware will automatically resolve the `{order}` route parameter via model binding and pass it to the policy method, throwing an `AuthorizationException` if the authenticated user is not authorized to perform the action on that specific order. This converts an authorization gap into a properly gated operation that respects both role and resource ownership.

## Behaviour changes

None. The `can:update,order` middleware does not alter arguments, return values, or the route's observable contract—it adds the missing authorization check that should have been there. The route parameter binding, controller invocation, and response remain unchanged. The only behavioural difference is that unauthorized requests now receive a 403 response instead of succeeding, which is the intended fix.
