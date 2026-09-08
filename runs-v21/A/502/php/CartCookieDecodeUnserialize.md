## Verdict
The vulnerability is confirmed. Line 12 of CartCookie.php calls `unserialize()` on data derived from an untrusted cookie value, permitting object injection attacks. The base64-decoded payload should not be deserialized with PHP's native serializer.

## Source
The `CartCookie::decode()` method receives a base64-encoded string from the `cart` cookie (via CartController). After base64-decoding, it directly deserializes the result without restricting object instantiation. An attacker can craft a malicious serialized object, base64-encode it, and inject it as the cookie value. Upon deserialization, PHP instantiates arbitrary classes and invokes their magic methods (`__wakeup`, `__destruct`, etc.), potentially leading to object injection chains that execute attacker-controlled code.

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

        $decoded = json_decode($payload, true);
        return is_array($decoded) ? $decoded : ['items' => []];
    }
}
```

## Explanation
The fix replaces `unserialize()` with `json_decode()`. JSON is a safe, text-based data format that cannot instantiate arbitrary objects—it deserializes only primitive types and arrays. The `true` flag in `json_decode()` returns an associative array instead of an object, matching the application's expectation. The validation `is_array($decoded)` ensures robustness: if the JSON decodes to a non-array value (e.g., a string or null), the method returns the safe default `['items' => []]`, preserving the original error-handling behavior. This eliminates object injection while maintaining API compatibility with CartController's data access patterns.
