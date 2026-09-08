## Verdict

VULNERABLE. CWE-502 confirmed: Untrusted cookie data is deserialized without class instantiation restrictions, enabling object injection and remote code execution via PHP gadget chains or magic methods.

## Source

Untrusted cookie value `$cookies['cart']` flows into `CartController::restore()` → `CartCookie::decode()` → `unserialize()` at line 12 of CartCookie.php without the `allowed_classes` restriction.

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

The vulnerability occurs because `unserialize()` by default instantiates any class present in the serialized payload, invoking magic methods (`__wakeup()`, `__destruct()`, `__toString()`) that attackers can chain to execute arbitrary code through gadget chains. The fix adds the `['allowed_classes' => false]` option (PHP 7.0+), which prevents object instantiation entirely and converts any serialized objects to `__PHP_Incomplete_Class` instances—preserving array and scalar data while blocking all magic method execution. Since the payload contains only data (cart items and coupon strings), not business objects, disabling object construction closes the injection vector without changing the wire format or breaking legitimate cart restoration.

## Behaviour changes

- Objects in serialized payloads become `__PHP_Incomplete_Class` instead of instantiated objects
- No magic methods (`__wakeup`, `__destruct`, `__toString`) are executed
- Array and scalar data (items, coupon) deserialize unchanged and remain accessible via array access
- The fix preserves backward compatibility with existing serialized cookies
- Gadget chain exploitation is prevented; RCE vector is closed
