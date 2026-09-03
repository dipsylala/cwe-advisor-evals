## Verdict

Exploitable. The authorization check is present but ignored, allowing any authenticated user to modify any order regardless of ownership or role.

## Source

The `Order` model instance passed to the `update()` controller method through route model binding (`Request $request, Order $order`), which is attacker-controllable via the URL parameter (`PUT /orders/{order}`).

## Fix

**Vulnerable code:**
```php
// SAST FINDING: CWE-862 (Missing Authorization) reported here. Sink is the next statement.
Gate::allows('update', $order);

$order->shipping_address = $validated['shipping_address'];
$order->status = $validated['status'];
$order->save();
```

**Fixed code:**
```php
// Authorization check that throws an exception if not authorized
Gate::authorize('update', $order);

$order->shipping_address = $validated['shipping_address'];
$order->status = $validated['status'];
$order->save();
```

## Explanation

The original code calls `Gate::allows('update', $order)` but discards its return value, leaving no enforcement of the authorization decision. `Gate::allows()` returns a boolean but does not abort execution on failure—the method is purely evaluative and requires an explicit check by the caller to enforce the decision. The fix replaces it with `Gate::authorize('update', $order)`, which throws an `AuthorizationException` if authorization fails. Laravel's exception handler automatically converts this to a 403 Forbidden response, and the authorization is now enforced before the order is modified.

## Behaviour changes

- **Return behavior changed**: `Gate::allows()` returns a boolean (discarded); `Gate::authorize()` returns void on success and throws on failure instead of returning false. This is the intended semantic change to enforce the authorization decision.
- **Exception on denial**: Unauthorized access now throws `AuthorizationException` (converted to 403 HTTP response) rather than silently continuing. This is a security fix, not a regression—the original code was allowing unauthorized access.

No other behavior changes. The method signature, route binding, validation, and response remain identical. The authorization decision is now enforced at the gate rather than evaluated and ignored.
