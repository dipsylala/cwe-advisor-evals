## Verdict

VULNERABLE - The authorization check logic is inverted.

## Source

```php
if (! $user->isAdmin()) {
    return Order::all();
}

return Order::where('user_id', $user->id)->get();
```

Non-admin users receive all orders in the system; admin users receive only filtered orders. This is backwards authorization logic.

## Fix

```php
if ($user->isAdmin()) {
    return Order::all();
}

return Order::where('user_id', $user->id)->get();
```

Reverse the condition: return all orders when the user IS an admin, and return only the user's own orders otherwise.

## Explanation

The original code grants unrestricted access (`Order::all()`) to non-admin users, violating the principle that sensitive data should only be accessible to authorized parties. The condition is logically inverted—the negation operator (`!`) causes non-admin users to trigger the all-orders branch.

The fix inverts the condition to check `$user->isAdmin()` directly, so admins see all orders and non-admin users see only their own orders. This aligns the authorization logic with the intended privilege model: admins have elevated access; regular users see scoped data.
