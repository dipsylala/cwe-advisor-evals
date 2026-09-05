## Verdict

**Confirmed** — CWE-862 (Missing Authorization)

The authorization logic is inverted. Non-admin users reach line 16 and retrieve all orders in the system, while admin users are restricted to their own orders only.

## Source

**File:** OrderController.php, line 16  
**Code path:** `OrderController::index()` → line 16 return statement

**Data flow:**
- Request reaches unauthenticated or non-admin user
- Condition `! $user->isAdmin()` evaluates true
- Line 16 executes: `return Order::all()`
- Attacker-controllable status (authenticated user without admin role) flows to the database query sink with no authorization constraint

**Sink contract:**
- `Order::all()` executes a SELECT query with no WHERE clause and returns all order records
- The caller uses the result directly as the HTTP response body without any filtering

## Fix

**Vulnerable code:**
```php
public function index(Request $request): iterable
{
    $user = $request->user();

    if (! $user->isAdmin()) {
        // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
        return Order::all();  // ← Non-admin users retrieve all orders
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
        // Admin users can view all orders
        return Order::all();
    }

    // Non-admin users can only view their own orders
    return Order::where('user_id', $user->id)->get();
}
```

## Explanation

The authorization check is inverted. The original code grants full database access to unauthenticated or non-admin users and restricts admin users to their own data. The fix swaps the condition so non-admin users are scoped to their own orders via a WHERE clause, while only authenticated admins reach the unrestricted `Order::all()` query. This follows the principle that sensitive operations default to deny and require explicit authorization to grant access. Authorization now enforces role-based access control at the query level, preventing unauthorized retrieval of system-wide order data.

## Behaviour changes

- **Non-admin users:** Now receive only orders where `user_id` matches their own user ID (404 or empty result set for unowned orders)
- **Admin users:** Continue to receive all orders in the system
- **HTTP status:** Remains 200 for authorized requests; no change to response structure
- **Database query:** Non-admin path now includes `WHERE user_id = ?` constraint; admin path unchanged
