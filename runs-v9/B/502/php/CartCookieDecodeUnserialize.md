## Verdict

Exploitable. CWE-502 (Deserialization of Untrusted Data), confidence: high.

- Location: `CartCookie.php:12`, inside `CartCookie::decode()`
- Sink: `unserialize($payload)`

## Source

`CartController::restore(array $cookies)` reads `$cookies['cart'] ?? ''` (an HTTP cookie value, fully attacker-controlled) and passes it unmodified to `CartCookie::decode($encoded)` (`CartController.php:9-10`).

`CartCookie::decode()` base64-decodes the value with strict mode (`base64_decode($encoded, true)`), which only rejects strings containing non-base64 characters - it does not validate or authenticate the decoded payload in any way. The result is handed directly to `unserialize($payload)` with no HMAC/integrity check and no `allowed_classes` restriction, so `unserialize()` is called on data an attacker fully controls via a request cookie. This matches the primary PHP CWE-502 taint sink with no mitigating control anywhere on the path.

Sink contract before the fix: `unserialize()` returns the reconstructed value (array, scalar, or arbitrary object graph) on success, or `false` with an `E_WARNING` on malformed input; that failure case is not checked by the caller. The method's declared return type is `mixed`, and the only argument PHP's `unserialize()` accepts beyond the payload - `options['allowed_classes']` - is omitted, so it defaults to allowing every autoloadable class to be instantiated, including any with exploitable `__wakeup()`, `__destruct()`, or `__toString()` magic methods (PHP object injection / gadget-chain RCE).

## Fix

No third-party library is required - PHP's built-in `json_decode()` is the guidance's primary replacement for `unserialize()` on untrusted input.

Vulnerable code (`CartCookie.php`):

```php
public static function decode(string $encoded): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false) {
        return ['items' => []];
    }

    return unserialize($payload); // CWE-502: unserialize() on attacker-controlled cookie data
}
```

Fixed code:

```php
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
```

## Explanation

The fix replaces `unserialize()` with `json_decode($payload, true)`, which parses the payload as plain data - it never instantiates PHP objects or invokes magic methods, so the gadget-chain/object-injection route is closed regardless of what classes are autoloadable in the application. `json_decode()` is used with `associative = true` so the result is a plain array, matching the array shape (`items`, `coupon` keys) `CartController::restore()` already expects from `unserialize()`'s array case, so no caller-side change is needed.

## Behaviour changes

- Added an explicit `is_array($cart)` check with a fallback to `['items' => []]` for a malformed or non-array payload. This is necessary because `json_decode()` returns `null` on invalid JSON where `unserialize()` returned `false` on invalid input - neither failure was previously checked, and the unchecked `false`/`null` was left to reach `CartController::restore()`'s `$cart['items'] ?? []` / `$cart['coupon'] ?? null` access, which degrades gracefully in both cases to the same empty-cart result. The added check makes that failure path explicit rather than relying on the caller's null-coalescing operator, but produces the same caller-visible outcome.
- Assumption (autonomous mode, no reviewer available to confirm): the code that originally *writes* the cart cookie is not part of the two-file call chain provided, so it could not be inspected. This fix assumes that producer is (or will be) updated to serialize the cart with `json_encode()` instead of PHP `serialize()` before base64-encoding it; otherwise, legitimately-issued cookies written by the old encoder will fail to decode under `json_decode()` and fall back to an empty cart. This does not weaken the fix - it only affects functional compatibility with an unseen encode path - but it should be verified against that file before deployment. Confidence is otherwise high because the sink, source, and absence of any mitigating control are all directly visible in the two provided files.
