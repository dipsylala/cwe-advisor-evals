## Verdict

Confirmed. The `unserialize()` call on line 12 of `CartCookie.php` deserializes attacker-controlled data (from an HTTP cookie) without any restrictions, allowing an attacker to instantiate arbitrary classes and trigger magic methods for remote code execution via gadget chains.

## Source

**Call chain:**
1. `CartController::restore()` receives `$cookies` array from HTTP request
2. Extracts `$cookies['cart']` (attacker-controlled via HTTP Cookie header)
3. Passes to `CartCookie::decode($encoded)`
4. Base64-decodes to `$payload` (line 7)
5. Passes directly to `unserialize($payload)` without restrictions (line 12)

**Risk:** An attacker can craft a serialized PHP object within the cookie that, upon deserialization, instantiates arbitrary classes and invokes magic methods (`__wakeup()`, `__destruct()`, `__toString()`) to execute arbitrary code through PHP object gadget chains.

## Fix

**Vulnerable code (line 12):**
```php
return unserialize($payload);
```

**Fixed code:**
```php
return unserialize($payload, ['allowed_classes' => false]);
```

## Explanation

The fix adds the `['allowed_classes' => false]` option to `unserialize()`, which was introduced in PHP 7.0. This option prevents the instantiation of any classes during deserialization—any serialized object in the payload becomes an `__PHP_Incomplete_Class` instance instead, and no magic methods are invoked.

This is the correct fix for this case because the deserialized data is expected to contain only arrays and scalar values (a shopping cart with items and a coupon code). The calling code in `CartController::restore()` accesses the result as an associative array with array access (`$cart['items']`, `$cart['coupon']`), not as object instances. Arrays and scalar values deserialize normally with `allowed_classes => false`, so functionality is fully preserved while eliminating the magic-method gadget-chain vector.

## Behaviour changes

**Before fix:**
- `unserialize($payload)` can instantiate arbitrary classes from the cookie payload
- Magic methods like `__wakeup()` and `__destruct()` execute during deserialization
- Attacker can leverage gadget chains in loaded libraries to achieve RCE

**After fix:**
- Objects in the payload are converted to `__PHP_Incomplete_Class` instances (no instantiation)
- No magic methods are invoked
- Arrays and scalar values (strings, integers, booleans, null) deserialize normally and unchanged
- Cart functionality is preserved: `$cart['items']` and `$cart['coupon']` work as before
- Gadget chain exploitation is prevented—there are no instantiated objects to chain through

The wire format and storage format remain unchanged (PHP-serialized cookies continue to work), and no legitimate cart data is lost.
