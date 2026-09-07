## Verdict
Exploitable. The `unserialize()` call on line 21 deserializes untrusted cookie data without restricting class instantiation, allowing an attacker to trigger magic methods and exploit gadget chains during object construction.

## Source
`$_COOKIE['cart_state']` - Untrusted HTTP cookie data read on line 18, stored in `$rawCookie`.

## Fix

**Vulnerable code (line 21):**
```php
$cart = unserialize($rawCookie);
```

**Fixed code:**
```php
$cart = unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]]);
```

## Explanation
The fix adds the `allowed_classes` option to `unserialize()`, restricting object construction to the `ShoppingCart` class only. This prevents instantiation of arbitrary classes that an attacker could exploit through magic methods (`__wakeup()`, `__destruct()`, `__toString()`) or gadget chains, while preserving the legitimate behavior for expected `ShoppingCart` objects. The existing `instanceof` check on line 23 already validates the type, confirming that the payload legitimately carries this class. The option is available in PHP 7.0+.

## Behaviour changes
None. The `allowed_classes` option restricts what can be instantiated during deserialization but does not change the behavior for legitimate `ShoppingCart` instances that pass the `instanceof` check on line 23 or trigger the fallback empty cart on line 24. The function contract—returning a `ShoppingCart` or a new empty one—remains identical.
