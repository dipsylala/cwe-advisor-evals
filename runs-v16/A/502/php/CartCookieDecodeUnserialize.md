## Verdict

Confirmed. Line 12 of CartCookie.php calls `unserialize()` on untrusted base64-decoded data without restricting object deserialization. An attacker can craft a serialized payload containing a gadget chain to achieve remote code execution.

## Source

```php
public static function decode(string $encoded): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false) {
        return ['items' => []];
    }

    return unserialize($payload);  // Line 12: Untrusted deserialization
}
```

CartController::restore() passes user-supplied cookie data to CartCookie::decode(), which unserializes it without object restrictions. The cookie is attacker-controlled and base64 encoding provides no protection against object injection.

## Fix

Disable object deserialization by passing the `allowed_classes` option to `unserialize()`:

```php
return unserialize($payload, ['allowed_classes' => false]);
```

This preserves the serialized wire format (no breaking changes to existing cookies) while preventing object instantiation, which blocks gadget chain exploitation.

## Explanation

PHP's `unserialize()` is vulnerable to object injection when processing untrusted data. An attacker can include a serialized object that triggers `__wakeup()`, `__destruct()`, or other magic methods during deserialization, potentially chaining through application gadgets to reach dangerous functions.

The cart cookie needs only scalar values (`items` array and `coupon` string). The fix uses `allowed_classes => false` (available since PHP 7.0) to deserialize only primitive types and arrays, completely disabling object instantiation. This maintains backward compatibility with existing serialized cart data while eliminating the injection vector.
