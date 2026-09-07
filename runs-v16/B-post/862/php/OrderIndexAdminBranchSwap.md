## Verdict

**CONFIRMED** - Missing Authorization (CWE-862). The index method checks whether the user is NOT an admin, then returns all orders. This inverted condition allows any authenticated non-admin user to enumerate all orders in the system, violating the expected authorization model where admins see all orders and regular users see only their own.

## Source

**File**: OrderController.php, line 16  
**Code**:
```php
if (! $user->isAdmin()) {
    return Order::all();  // Returns ALL orders for non-admin users
}
```

**Data flow**: The `$user` is loaded from the authenticated request. The conditional checks `isAdmin()` status. When the user is NOT an admin, the sink `Order::all()` executes without further authorization, exposing all orders.

## Fix

**Vulnerable code**:
```php
public function index(Request $request): iterable
{
    $user = $request->user();

    if (! $user->isAdmin()) {
        // CWE-862: Returns ALL orders to non-admin users - inverted logic
        return Order::all();
    }

    return Order::where('user_id', $user->id)->get();
}
```

**Fixed code**:
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

The authorization check was inverted: the condition `! $user->isAdmin()` should have been `$user->isAdmin()`. Removing the negation operator restores the intended authorization logic: admins receive all orders via `Order::all()`, while non-admin users receive only their own orders via the scoped query `Order::where('user_id', $user->id)->get()`. This ensures every user can access only the data they are permitted to see, closing the exposure.

## Behaviour changes

- **Before fix**: All authenticated non-admin users receive every order in the system.
- **After fix**: Non-admin users receive only their own orders; admins receive all orders.
- **Authorization model**: The scoped access pattern (non-admin sees user_id-matching records) now works as intended.
