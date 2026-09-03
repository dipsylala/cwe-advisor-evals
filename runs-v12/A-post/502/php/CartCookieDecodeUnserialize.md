## Verdict

Confirmed. The `unserialize()` call at line 12 deserializes untrusted cookie data without safeguards, allowing arbitrary object instantiation and code execution through magic methods.

## Source

```php
final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        return unserialize($payload);
    }
}
```

The cookie data flows untrusted from the client through `base64_decode()` into `unserialize()`, which can instantiate arbitrary classes and trigger magic methods (`__wakeup()`, `__destruct()`, `__toString()`, etc.) during deserialization.

## Fix

Replace `unserialize()` with `json_decode()`:

```php
final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        $decoded = json_decode($payload, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['items' => []];
        }

        return $decoded;
    }
}
```

## Explanation

`unserialize()` reconstructs PHP objects from their serialized form, automatically triggering magic methods during deserialization. An attacker controlling the cookie can craft a malicious serialized payload targeting known object injection gadget chains in loaded classes, leading to arbitrary code execution.

`json_decode()` parses only JSON structure and never instantiates objects—it returns associative arrays and primitives only. This eliminates the instantiation vector entirely. The function is safe for untrusted input as long as error handling confirms successful parsing (checked via `json_last_error()`). For cart data (structured key-value storage), JSON is a natural fit and maintains the same data shape.

Both the base64 wrapping and JSON transport are standard practice for cookie integrity; JSON is widely used and requires no additional dependencies beyond PHP's standard library.
