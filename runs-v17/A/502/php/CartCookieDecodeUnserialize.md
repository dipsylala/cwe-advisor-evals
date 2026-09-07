## Verdict

The vulnerability is confirmed. Line 12 of CartCookie.php uses `unserialize()` on untrusted cookie data without restricting the classes that can be instantiated, enabling object injection attacks.

## Source

**CartCookie.php (line 12):**
```php
return unserialize($payload);
```

The `$payload` variable contains base64-decoded cookie data from user input, passed through CartController::restore() from the `$_COOKIE` superglobal.

## Fix

### File: CartCookie.php

```php
<?php

final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        return unserialize($payload, ['allowed_classes' => false]);
    }
}
```

## Explanation

PHP's `unserialize()` function is vulnerable to object injection when deserializing untrusted data. An attacker can craft a malicious serialized payload that instantiates arbitrary classes and invokes their magic methods (`__wakeup()`, `__destruct()`, etc.), potentially leading to arbitrary code execution.

The fix uses the `allowed_classes` option introduced in PHP 7.0.0 with value `false` to disable object instantiation entirely. This allows deserialization of primitive types (strings, numbers, arrays, booleans, null) while preventing object instantiation. Since the cart data only needs to store arrays and primitive values ('items' array and 'coupon' field), this restriction is safe and eliminates the attack surface.

This approach follows the defense-in-depth principle: validate the data format (disallow objects) rather than attempting to whitelist safe classes, which is difficult to maintain and may miss gadget chains.
