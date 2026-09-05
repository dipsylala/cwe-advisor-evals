## Verdict
exploitable

## Source
`$request->user()` on line 12 returns the authenticated user from the HTTP request.

## Fix

**Vulnerable code (line 14–16):**
```php
if (! $user->isAdmin()) {
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    return Order::all();
}
```

**Fixed code:**
```php
use Illuminate\Support\Facades\Gate;

// ... in the index method:

if ($user->isAdmin()) {
    Gate::authorize('viewAll', Order::class);
    return Order::all();
}

Gate::authorize('viewOwn', Order::class);
return Order::where('user_id', $user->id)->get();
```

## Explanation
The original code has two authorization defects: an inverted condition and no explicit authorization checks. The condition `if (! $user->isAdmin())` causes non-admin users to receive all orders, while admin users receive only their own—the opposite of intended behavior. The fix inverts the condition to restore the correct logic and adds explicit `Gate::authorize()` calls at each code path to enforce that non-admin users can only view their own orders and admin-level access is guarded. Each authorization check must be registered as a gate in `AppServiceProvider::boot()` or as a Policy method (defined via `php artisan make:policy OrderPolicy --model=Order`); the authorization framework throws `AuthorizationException` on denial, which Laravel converts to HTTP 403.

## Behaviour changes
The fix adds two Gate authorization checks that were previously absent. These checks will throw `Illuminate\Auth\Access\AuthorizationException` if the gate denies access, resulting in an HTTP 403 response. Non-admin users attempting to access the endpoint when the `viewOwn` gate is not defined or fails will receive 403 instead of 200. If the gates are not registered before the authorization calls execute, the application will throw an exception at runtime. The authorization framework must be configured with matching gate or policy definitions before this fix is deployed.
