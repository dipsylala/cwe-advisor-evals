## Verdict

The vulnerability is **confirmed**. Line 12 in CartCookie.php calls `unserialize()` on untrusted data decoded from a user-supplied cookie, allowing object injection attacks.

## Source

The attack surface spans two files:
1. **CartController.php:9-10** — accepts cookie data from the user and passes it to `CartCookie::decode()`
2. **CartCookie.php:12** — deserializes the cookie payload with `unserialize($payload)` without validation

The data flow is untrusted (user cookies) → base64-decode → unserialize, with no type or structure validation.

## Fix

Replace `unserialize()` with `json_decode()` to safely deserialize only scalar data and arrays:

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
        if (!is_array($decoded)) {
            return ['items' => []];
        }
        return $decoded;
    }
}
```

Update CartController.php to serialize the cart as JSON before encoding:

```php
// When storing the cart in a cookie:
$json = json_encode(['items' => $cart['items'], 'coupon' => $cart['coupon']]);
$encoded = base64_encode($json);
// Store $encoded in the cookie
```

## Explanation

`unserialize()` in PHP can instantiate arbitrary objects and trigger magic methods (`__wakeup`, `__destruct`, etc.), enabling object injection attacks that lead to remote code execution if exploitable classes exist in the application. Cookies are user-controlled and untrusted.

JSON serialization is inherently safer: it can only represent scalar values, arrays, and null — no objects. The cart data structure (items array and optional coupon) is perfectly representable as JSON. `json_decode()` with the second parameter `true` returns only arrays and scalars, never objects.

The added type check `is_array($decoded)` ensures the decoded value is an array before use, rejecting malformed or malicious payloads that might contain raw scalars instead.
