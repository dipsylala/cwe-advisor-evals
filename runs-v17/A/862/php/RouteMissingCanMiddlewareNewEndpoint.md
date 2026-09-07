## Verdict

Valid CWE-862 (Missing Authorization). The delete route for purging orders lacks authorization middleware and allows any authenticated user to purge any order.

## Source

Lines 24-25 of `routes_orders.php`. The route definition:

```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
```

Only `auth:sanctum` is wired up, confirming the caller is logged in but not whether they are allowed to act on this specific order.

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

The purge endpoint performs a sensitive operation (removing a row and its line items) that is at least as critical as the update operation, yet it was missing the authorization middleware. By adding `can:update,order` to the middleware array, the route now enforces that the authenticated user must be authorized to update the specific order before the purge controller action is invoked. This aligns with the authorization pattern used on other mutating routes (update and cancel) and prevents unauthorized users from purging arbitrary orders they do not own or manage.
