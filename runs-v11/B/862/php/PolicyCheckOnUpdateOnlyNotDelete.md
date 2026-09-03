## Verdict

exploitable

## Source

The `destroy()` method at line 32-38 calls `$order->delete()` at line 35 without any authorization check. The `$order` parameter is resolved by Laravel's route model binding from a request identifier. The preceding controller methods (`show()` and `update()`) both call `Gate::authorize()` before their respective operations, establishing the pattern that `destroy()` fails to follow.

## Fix

**Vulnerable code:**

```php
public function destroy(Order $order)
{
    // SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
    $order->delete();

    return response()->json(null, 204);
}
```

**Fixed code:**

```php
public function destroy(Order $order)
{
    Gate::authorize('delete', $order);

    $order->delete();

    return response()->json(null, 204);
}
```

## Explanation

The `destroy()` method performs a sensitive state-change operation without verifying the authenticated user holds the required permission. The pattern established by `show()` (line 13) and `update()` (line 20) demonstrates that authorization checks are applied through `Gate::authorize()` for comparable sensitive actions. Adding `Gate::authorize('delete', $order)` at the start of `destroy()` enforces the same requirement, resolving the ownership and resource-level access control before the delete operation executes. Laravel's gate will throw `AuthorizationException` if the authorization check fails, which the framework converts to a 403 Forbidden response by default.

## Behaviour changes

none
