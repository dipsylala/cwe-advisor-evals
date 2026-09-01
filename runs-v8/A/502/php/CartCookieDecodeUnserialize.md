## Verdict

CWE-502: Deserialization of Untrusted Data confirmed on line 12. The `unserialize()` function processes a base64-decoded cookie value without validation, creating an object injection vulnerability.

## Source

User-supplied cookie data (`$cookies['cart']`) flows through `CartController::restore()` to `CartCookie::decode()` where it is base64-decoded and then unserialized.

## Fix

Replace `unserialize()` with `json_decode()` for safer deserialization:

```php
final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        $data = json_decode($payload, true);
        if (!is_array($data)) {
            return ['items' => []];
        }

        return $data;
    }
}
```

When encoding the cart for the cookie, use `json_encode()` instead of `serialize()`:

```php
$encoded = base64_encode(json_encode($cartData));
```

## Explanation

PHP's `unserialize()` is unsafe with untrusted data because it instantiates arbitrary objects, potentially triggering magic methods (`__wakeup()`, `__destruct()`) that form gadget chains leading to arbitrary code execution.

JSON encoding avoids this by restricting data to primitives and arrays—no object instantiation occurs during decoding. Since a shopping cart contains only items and coupons (scalars and arrays), JSON is a safer, standard-compliant alternative.

The fix also adds a type check after decoding to ensure malformed JSON gracefully returns a default cart structure rather than propagating invalid data.
