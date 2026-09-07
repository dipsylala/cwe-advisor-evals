## Verdict

EXPLOITABLE. The `unserialize()` call on line 21 accepts untrusted data from the `$_COOKIE` superglobal without restricting which classes may be instantiated. An attacker can craft a malicious serialized payload to instantiate arbitrary classes and trigger magic methods (`__wakeup()`, `__destruct()`), enabling remote code execution via gadget chains. The `instanceof` check on line 23 occurs after deserialization is complete and does not prevent magic-method execution during object construction.

## Source

File: `evals/cases/502/php/UnserializeCookieData/UnserializeCookieData.php`

Lines: 16-24

Data flow:
1. Line 16: Attacker-controlled input source — `$_COOKIE['cart_state']`
2. Line 17: Copied to local variable — `$rawCookie = $_COOKIE['cart_state']`
3. Line 21: Unsafe sink — `unserialize($rawCookie)` with no class restrictions
4. Lines 23-24: Validation occurs too late (after deserialization)

## Fix

On line 21, add the `allowed_classes` parameter to restrict deserialization to only the `ShoppingCart` class:

```php
// Before:
$cart = unserialize($rawCookie);

// After:
$cart = unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]]);
```

This change restricts which classes may be instantiated from the serialized cookie data, preventing arbitrary class instantiation and gadget-chain attacks while preserving the legitimate deserialization of `ShoppingCart` objects.

## Explanation

PHP's `unserialize()` function reconstructs arbitrary objects from serialized data, including invoking magic methods like `__wakeup()` and `__destruct()` during object construction. Without an `allowed_classes` restriction, an attacker can set a malicious serialized payload in the `$_COOKIE` superglobal to instantiate dangerous classes from the application's codebase, triggering property-oriented programming (POP) gadget chains to execute arbitrary code.

The fix passes `['allowed_classes' => [ShoppingCart::class]]` as the second parameter to `unserialize()`. This restricts deserialization to only the `ShoppingCart` class; any other serialized object in the cookie becomes an `__PHP_Incomplete_Class` instance instead. The existing `instanceof ShoppingCart` check on line 23 ensures that only properly deserialized `ShoppingCart` objects are used; malicious payloads are rejected and a default empty cart is returned instead.

This approach preserves the existing wire format (serialized PHP objects in the cookie) and maintains backward compatibility with legitimate cart data already stored in users' cookies.

## Behaviour changes

- Valid `ShoppingCart` objects serialized in cookies continue to deserialize successfully and pass the `instanceof` check; application behavior is unchanged for legitimate users.
- Malicious payloads containing serialized objects of arbitrary classes are rejected; they deserialize to `__PHP_Incomplete_Class`, fail the `instanceof ShoppingCart` check, and return a default empty cart instead of executing gadget chains.
- Performance: negligible; the `allowed_classes` parameter adds no significant overhead.
