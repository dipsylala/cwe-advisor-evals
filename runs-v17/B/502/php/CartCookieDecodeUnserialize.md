## Verdict

Confirmed exploitable. The `unserialize()` call on line 12 of CartCookie.php receives base64-decoded data from an untrusted cookie. Without restrictions on class instantiation, an attacker can craft a malicious serialized object with gadget chains to execute arbitrary code during deserialization.

## Source

**Location:** CartCookie.php, line 12

**Data Flow:**
- Cookie `$cookies['cart']` (untrusted) → CartController::restore()
- `$encoded = $cookies['cart']` (user-controlled)
- `base64_decode($encoded, true)` → `$payload`
- `unserialize($payload)` ← **Sink (line 12)**

**Attack Vector:** An attacker sets a malicious `cart` cookie containing a base64-encoded serialized PHP object with embedded gadget chains. Upon decode, the magic methods are invoked during deserialization, allowing code execution.

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

The fix adds the `['allowed_classes' => false]` option to the `unserialize()` call, preventing instantiation of any classes during deserialization. When `allowed_classes` is `false`, any serialized object becomes an instance of `__PHP_Incomplete_Class`, and no magic methods (`__wakeup()`, `__destruct()`, `__toString()`) are invoked.

This approach preserves the existing wire format and data integrity - legitimate serialized cart data (arrays containing items and coupons) continues to decode correctly because scalars and arrays are not affected by the restriction. The code flow in CartController remains unchanged: array access operations (`$cart['items']`, `$cart['coupon']`) work identically for data-only payloads.

This is the appropriate fix because:
1. The payload is data-only (arrays and scalars, no legitimate objects)
2. The cookie was written by `serialize()` elsewhere in the system (the default empty return `['items' => []]` confirms the contract)
3. No format change is required, avoiding a breaking change to existing cookies

## Behaviour changes

**Before fix:**
- Arbitrary classes could be deserialized and instantiated
- Magic methods (`__wakeup`, `__destruct`, `__toString`) execute during deserialization
- Gadget chains in malicious payloads can lead to remote code execution

**After fix:**
- All deserialized objects become `__PHP_Incomplete_Class` instances
- No magic methods are invoked
- Data-only payloads (arrays, scalars) decode correctly and maintain full data fidelity
- Application behavior is unchanged for legitimate traffic
- Gadget chain attacks are prevented
