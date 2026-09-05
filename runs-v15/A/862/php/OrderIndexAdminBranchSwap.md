## Verdict

Authorization logic is inverted, allowing non-admin users to access all orders while restricting admins to their own orders. This is the inverse of intended access control.

## Source

Lines 14-19 in `OrderController.php`:

```php
if (! $user->isAdmin()) {
    return Order::all();
}

return Order::where('user_id', $user->id)->get();
```

The conditional negates the admin check, so non-admin users enter the first branch and execute `Order::all()`.

## Fix

Swap the return statements so admins receive all orders and non-admins receive only their own:

```php
if (! $user->isAdmin()) {
    return Order::where('user_id', $user->id)->get();
}

return Order::all();
```

Alternatively, remove the negation operator:

```php
if ($user->isAdmin()) {
    return Order::all();
}

return Order::where('user_id', $user->id)->get();
```

## Explanation

The vulnerability stems from an inverted authorization condition. The `!$user->isAdmin()` check allows non-admin users to bypass restriction and retrieve all orders in the database, while actual admins are limited to their own records. The fix restores correct access control: non-admin users see only their own orders, and admins see all orders.
