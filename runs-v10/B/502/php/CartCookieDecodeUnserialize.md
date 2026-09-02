## Verdict

Confirmed. The vulnerability is real and exploitable. Line 12 in CartCookie.php calls `unserialize()` on base64-decoded user-controlled cookie data without integrity verification or class restrictions. This allows arbitrary object instantiation and gadget chain exploitation.

## Source

**File**: `CartCookie.php`, line 12

Data flow: `$cookies['cart']` (user-controlled) → `base64_decode()` → `unserialize()` (sink)

The `CartController::restore()` method passes untrusted cookie data to `CartCookie::decode()`, which deserializes it without validation.

```php
public static function decode(string $encoded): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false) {
        return ['items' => []];
    }

    return unserialize($payload);  // VULNERABLE - line 12
}
```

## Fix

Replace PHP's native serialization with JSON, which cannot instantiate arbitrary classes:

```php
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
```

The serialized cart cookie must also be written using `json_encode()` instead of `serialize()` wherever it is created.

If maintaining backward compatibility with existing serialized cookies is required, use HMAC-SHA256 integrity validation:

```php
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

public static function encode(array $data, string $secret): string
{
    $json = json_encode($data);
    $signature = hash_hmac('sha256', $json, $secret, true);
    return base64_encode($signature . $json);
}

public static function decodeWithSignature(string $encoded, string $secret): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false || strlen($payload) < 32) {
        return ['items' => []];
    }

    $signature = substr($payload, 0, 32);
    $json = substr($payload, 32);
    
    if (!hash_equals($signature, hash_hmac('sha256', $json, $secret, true))) {
        return ['items' => []];
    }

    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        return ['items' => []];
    }
    return $decoded;
}
```

## Explanation

PHP's `unserialize()` instantiates arbitrary classes during deserialization and invokes magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution through gadget chains in loaded libraries.

The primary fix replaces `unserialize()` with `json_decode()`. JSON cannot instantiate classes and is therefore safe. The cart data structure (items array and coupon field) is simple data with no serialization-specific requirements, making JSON a direct replacement. This requires encoding cart cookies with `json_encode()` on the write side.

The secondary approach preserves backward compatibility by adding HMAC-SHA256 signature verification before any deserialization. The signature prevents tampering even if unserialize() is used. This adds integrity checking at the cost of complexity and does not eliminate the unserialize() weakness — use only if you cannot refactor away from PHP serialization.

The fix also validates that decoded data is an array, preventing non-array JSON values from being returned.

## Behaviour changes

- **Return type on invalid input**: Now returns `['items' => []]` for non-array JSON payloads, matching the behavior for invalid base64 or missing signatures.
- **Data format**: Cookies must be encoded with `json_encode()` instead of `serialize()` going forward. Existing serialized cookies become unreadable; migration requires a temporary dual-decode approach or cookie expiration.
- **Error handling**: `json_decode()` does not throw exceptions on invalid JSON; it returns `null`. This is handled by validating the result is an array.
- **No magic method execution**: Unlike unserialize(), json_decode() does not instantiate objects or invoke magic methods, eliminating the gadget chain risk entirely.
