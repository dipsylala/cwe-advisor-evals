## Verdict

Confirmed. The `unserialize()` call on line 12 of CartCookie.php deserializes untrusted user-controlled cookie data without integrity checks or class restrictions, enabling PHP object injection and potential remote code execution through magic method chains.

## Source

Line 12 in CartCookie.php:

```php
return unserialize($payload);
```

The `$payload` originates from `$cookies['cart']` (user-supplied), base64-decoded but not verified. The decoded data is passed directly to `unserialize()` without HMAC verification or class allowlisting.

## Fix

Replace `unserialize()` with `json_decode()`, which prevents object instantiation and gadget chains:

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

        $decoded = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
            return ['items' => []];
        }

        return $decoded;
    }
}
```

## Explanation

The fix replaces PHP's native `unserialize()` with `json_decode()`, which parses structured data without instantiating arbitrary classes. This eliminates the attack surface for object injection and magic method exploitation. The code validates that JSON decoding succeeded and returns a default safe array if the payload is malformed, preserving the existing error handling contract. No changes are required in CartController—it already accesses the result via array subscripts (`['items']`, `['coupon']`), which work identically with JSON-decoded arrays.

## Behaviour changes

- Deserialized data is now limited to JSON-compatible types (arrays, strings, numbers, booleans, null), no longer arbitrary PHP objects.
- Malformed or non-JSON payloads return `['items' => []]` instead of triggering a warning and returning false, providing consistent error handling.
- Existing serialized cookies will not decode; callers must either regenerate cookies in JSON format or accept a one-time cache miss on upgrade.
