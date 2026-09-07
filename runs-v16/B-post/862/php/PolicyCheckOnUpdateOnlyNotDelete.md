## Verdict

Exploitable

## Source

Authenticated HTTP request with an Order model parameter via route model binding. The route is accessible to any authenticated user without role or permission validation.

## Fix

**Vulnerable code (line 32-38):**
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

The `destroy()` method lacked an explicit authorization check before calling `$order->delete()`. The sibling methods `show()` and `update()` both use `Gate::authorize()` to verify the authenticated caller holds the required permission for the action and relationship to the resource. The missing check in `destroy()` allowed any authenticated user to delete any order they could guess the ID of, regardless of whether they owned it or had administrative permission. Adding `Gate::authorize('delete', $order)` at the method entry enforces the same authorization pattern, preventing unauthorized deletions by validating both the caller's delete capability and their relationship to the specific order being deleted.

## Behaviour changes

None. The authorization call throws `AuthorizationException` on denial, which Laravel converts to a 403 response by default and matches the existing error behaviour of the sibling methods. The call succeeds silently for authorized requests and proceeds to the delete, preserving the original contract. No return value, output, or implicit parameter changed.
