## Verdict

Confirmed. `CartCookie::decode()` passes an attacker-controlled cookie value (base64-decoded but otherwise unvalidated) directly to `unserialize()`. Any client can set the `cart` cookie to an arbitrary base64 payload; PHP's `unserialize()` will instantiate whatever classes the payload names and invoke their magic methods (`__wakeup`, `__destruct`, `__toString`, etc.), which is a classic PHP object-injection path into remote code execution or other gadget-chain abuse if any autoloaded class on the include path exposes a dangerous magic method.

## Source

`CartController::restore(array $cookies)` reads the raw cookie value from `$cookies['cart']` (attacker-controlled HTTP cookie input) and forwards it unmodified to `CartCookie::decode()`, which base64-decodes it and calls `unserialize($payload)` on line 12 - the sink.

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

        $cart = unserialize($payload, ['allowed_classes' => false]);
        if (!is_array($cart)) {
            return ['items' => []];
        }

        return $cart;
    }
}
```

## Explanation

The wire format (base64-wrapped PHP serialization) is left in place because it is a shared contract with whatever code writes the cart cookie; swapping to JSON here would silently break every existing cookie without a matching change on the encode side, which is outside this file. Instead, the fix removes the actual danger in the sink: `unserialize()` is now called with `['allowed_classes' => false]`, which decodes arrays and scalars but refuses to instantiate any object, regardless of what class name the payload specifies. That eliminates PHP object-injection and magic-method gadget chains entirely, since no class can ever be constructed from the cookie data - the attacker is limited to arrays/scalars, which is all a legitimate cart payload ever needed to carry.

The second change guards the return value: if `unserialize()` fails or returns something other than an array (a forged, truncated, or otherwise invalid payload, or the `false` unserialize returns on error), `decode()` now falls back to an empty cart (`['items' => []]`) instead of returning a non-array value that `CartController::restore()` would try to index. This preserves the existing behavior for empty/invalid cookies and keeps the same `items`/`coupon` array shape for legitimate cart data, while ensuring no attacker-supplied payload can produce a PHP object anywhere downstream.
