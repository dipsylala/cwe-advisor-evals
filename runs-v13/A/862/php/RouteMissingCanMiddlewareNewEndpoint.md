## Verdict

Authorization check missing.

## Source

```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware('auth:sanctum');
```

## Fix

```php
Route::delete('/orders/{order}/purge', [OrderController::class, 'purge'])
    ->middleware(['auth:sanctum', 'can:update,order']);
```

## Explanation

The endpoint only enforces authentication via `auth:sanctum`, confirming the user is logged in, but lacks authorization middleware to verify the user is permitted to act on the specific order being purged. Adding `can:update,order` applies the same authorization policy used by the mutating `update` and `cancel` routes, which is appropriate given that purging is described as at least as sensitive as updating. This prevents any authenticated user from purging arbitrary orders, restricting the operation to authorized users only.
