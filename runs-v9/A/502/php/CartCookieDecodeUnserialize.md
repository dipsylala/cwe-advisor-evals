## Verdict
Confirmed. `CartCookie::decode()` passes an attacker-controlled cookie value directly into PHP's `unserialize()`, allowing arbitrary object injection (PHP Object Injection), which can lead to remote code execution, SQL injection, or arbitrary file access depending on which classes with magic methods (`__wakeup`, `__destruct`, `__toString`, etc.) are autoloadable in the application.

## Source
`CartController::restore(array $cookies)` reads `$cookies['cart']` (an HTTP cookie value, fully attacker-controlled) and passes it unmodified to `CartCookie::decode()`, which base64-decodes it and calls `unserialize($payload)` on line 12 of `CartCookie.php`. No validation, allowlisting, or integrity check occurs anywhere on this path.

## Fix

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

        $cart = json_decode($payload, true);
        if (!is_array($cart)) {
            return ['items' => []];
        }

        return $cart;
    }

    public static function encode(array $cart): string
    {
        return base64_encode(json_encode($cart));
    }
}
```

## Explanation
The root cause is using PHP's native `unserialize()` on data that originates from a client-supplied cookie. `unserialize()` will instantiate any class named in the serialized payload that is autoloadable in the application, and invoke its magic methods (`__wakeup`, `__destruct`, `__toString`, `__invoke`, etc.) during or after construction. An attacker who can reach any "gadget chain" class in the codebase or its dependencies (a common occurrence with frameworks and ORMs) can use this to trigger file writes, SQL queries, SSRF, or code execution without ever calling that class directly.

The cart payload here is a simple associative array (`items`, `coupon`) with no need for PHP-specific object graph support, so the correct fix is to stop using PHP serialization for this data entirely rather than trying to sanitize it. Replacing `unserialize()`/`serialize()` with `json_decode()`/`json_encode()` removes the vulnerability class outright: JSON has no concept of object instantiation or magic methods, so a malicious cookie value can at worst produce malformed or unexpected array data, which is already handled by validating the decoded result `is_array()` before use (mirroring the existing `base64_decode(..., true)` strict-mode check for malformed input).

If PHP's native serialization format must be kept for backward compatibility with already-issued cookies, the minimum viable fix is to pass `['allowed_classes' => false]` as the second argument to `unserialize()`, which decodes scalars and arrays but converts any embedded object to an incomplete, inert `__PHP_Incomplete_Class` instance with no methods invoked — this closes the object-injection vector while keeping the wire format unchanged. Switching to JSON is preferred here because the cart never needs anything beyond arrays and scalars, and it also produces a cookie payload that is easier to inspect and audit than serialized PHP.

After the fix, verify by constructing a cookie value that would previously deserialize into a class with a `__wakeup` or `__destruct` side effect (e.g. a class that writes a file or throws) and confirming the fixed `decode()` either returns the empty-cart fallback or a plain array with no class instantiation, while a legitimate JSON-encoded cart cookie continues to round-trip through `encode()`/`decode()` correctly.
