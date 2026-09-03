## Verdict

Exploitable. The `CartCookie::decode()` method deserializes untrusted cookie data without integrity verification or class restrictions, creating a vector for gadget chain attacks or property-oriented programming exploits through PHP's `unserialize()` function.

## Source

User-supplied cookie value passed via `$cookies['cart']` to `CartController::restore()`, which forwards it to `CartCookie::decode()` as the `$encoded` parameter. Cookies are untrusted input controlled by the client.

## Fix

**Vulnerable code (CartCookie.php line 12):**

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

**Fixed code:**

```php
final class CartCookie
{
    public static function decode(string $encoded): mixed
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            return ['items' => []];
        }

        // Use JSON instead of unserialize() to prevent gadget chain attacks
        $data = json_decode($payload, true);
        if (!is_array($data)) {
            return ['items' => []];
        }

        return $data;
    }
}
```

## Explanation

The fix replaces PHP's `unserialize()` with `json_decode()`, which eliminates the attack vector. PHP serialization can instantiate arbitrary classes and trigger magic methods (`__wakeup()`, `__destruct()`, `__toString()`), potentially enabling remote code execution through gadget chains present in loaded libraries. JSON cannot execute code—it is purely data—and decoding a JSON string produces only arrays, objects, or scalar values without constructor invocation. This moves the code from relying on the integrity of untrusted input (which cannot be guaranteed) to using a safe data format where trust in the format itself is sufficient. The `is_array()` guard preserves the original error-handling contract by returning an empty items array if the JSON is malformed or represents non-array data.

## Behaviour changes

**Serialization format change**: The cookie encoding must change from PHP serialization to JSON. Any code that currently encodes the cart data must use `json_encode()` instead of `serialize()`. Production systems encoding the cookie would change from `base64_encode(serialize(['items' => [...], 'coupon' => ...]))` to `base64_encode(json_encode(['items' => [...], 'coupon' => ...]))`.

**Backward compatibility**: Existing cookies in serialized PHP format will not decode correctly; they will fail the `is_array()` check and return the default `['items' => []]`. A migration strategy may be needed if existing sessions must remain valid (e.g., a temporary dual-format decoder or cookie invalidation).

**No other behavior changes**: The return type remains the same, the error-handling fallback remains equivalent, and the controller code that consumes the result requires no modification.
