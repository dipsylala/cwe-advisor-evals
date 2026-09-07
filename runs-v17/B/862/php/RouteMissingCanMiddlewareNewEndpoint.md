## Verdict

The authorization check is genuinely absent. The `purge` route applies only `auth:sanctum` middleware (authentication), not the `can` middleware (authorization) that comparable sensitive routes require.

## Source

Line 24 in routes_orders.php defines a route to delete (purge) an order. The route receives an order by route model binding (`{order}`), and the calling user is authenticated by the `auth:sanctum` middleware. However, there is no authorization check to verify the caller is permitted to purge this specific order.

## Fix

Apply the `can:update,order` middleware to the purge route, matching the authorization pattern established by the update and cancel routes.

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

The purge operation is a permanent deletion that affects data and state at least as sensitive as an update. The route now enforces authorization through the `can:update,order` middleware, which verifies the authenticated caller holds the required permission on the specific order instance. This check is centralized in a Policy class (expected to be defined in the codebase) and reused across all sensitive order operations. The middleware returns 403 Forbidden if the caller lacks permission, preventing the vulnerable action. The fix preserves all existing behavior for authorized callers while closing the gap that allowed any authenticated user to delete any order.

## Behaviour changes

- Authenticated users without the `update` permission on an order will receive a 403 Forbidden response instead of being able to purge the order
- Authorized users (those who can update the order, typically the order owner or a manager) retain the ability to purge the order
- The authorization check now follows the same centralized pattern as update and cancel operations, reducing the attack surface
