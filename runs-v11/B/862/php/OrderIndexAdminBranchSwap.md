## Verdict

Exploitable

## Source

**Location:** `evals/cases/862/php/OrderIndexAdminBranchSwap/OrderController.php`, line 16

**Authorization check:** `$user->isAdmin()` method call in the conditional logic

**Sensitive operation (sink):** `Order::all()` returns all orders in the database without resource-level authorization

**Issue:** The authorization logic is inverted. Non-admin users receive all orders via `Order::all()`, while admin users receive only their own orders via `Order::where('user_id', $user->id)->get()`. This allows any authenticated non-admin user to access the full order history, violating the expected authorization boundary.

## Fix

**Vulnerable code:**
```php
public function index(Request $request): iterable
{
    $user = $request->user();

    if (! $user->isAdmin()) {
        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return Order::all();  // ❌ Backwards: non-admins get ALL orders
    }

    return Order::where('user_id', $user->id)->get();
}
```

**Fixed code:**
```php
public function index(Request $request): iterable
{
    $user = $request->user();

    if ($user->isAdmin()) {
        return Order::all();
    }

    return Order::where('user_id', $user->id)->get();
}
```

## Explanation

The fix corrects the inverted authorization logic by removing the negation operator (`!`) from the `isAdmin()` check. Now the method returns all orders only when the user holds the admin role, and returns a scoped query of only the user's own orders for non-admin users. This aligns the implementation with the expected authorization policy: admins can see all orders, non-admins can see only their own. The sensitive operation `Order::all()` is now guarded by a proper role-based authorization check instead of being exposed to unauthenticated or unprivileged users.

## Behaviour changes

The only behavioral change is the corrected authorization decision:
- **Before:** Non-admin users received all orders; admin users received only their own orders
- **After:** Admin users receive all orders; non-admin users receive only their own orders

This restores the expected authorization model where sensitive data access is properly restricted based on user role. No method signatures, return types, database queries, or error handling behavior change beyond the corrected authorization scope.
