## Verdict

Exploitable.

## Source

`CartController::restore(array $cookies)` reads `$cookies['cart']` (the HTTP `cart` cookie, attacker-controlled) and passes it unchanged to `CartCookie::decode()`.

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

        return unserialize($payload, ['allowed_classes' => false]);
    }
}
```

## Explanation

`CartCookie::decode()` base64-decodes the raw `cart` cookie and passes the result straight into `unserialize()` with no options, so PHP will instantiate any class named in the payload and run its magic methods (`__wakeup()`, `__destruct()`, `__toString()`) during reconstruction - a classic PHP object-injection / gadget-chain sink, and the cookie is fully attacker-controlled. `CartController::restore()` only ever reads `$cart['items']` and `$cart['coupon']` from the decoded value with array access (`??`), never `instanceof`, a method call, or a typed property - so the legitimate payload is data only (arrays and scalars), not an object graph. Per the CWE-502 PHP guidance, that means the correct fix is to keep `unserialize()` (the wire format cookies already use, and the only producer of this value is external/legacy, not something this change can also update) and add `['allowed_classes' => false]` to the call. This makes any object encountered during unserialization come back as an inert `__PHP_Incomplete_Class` instance with no magic methods invoked, while arrays and scalars - the only shapes the legitimate cart payload actually uses - decode exactly as before.

## Behaviour changes

None for legitimate traffic: a cookie produced by serializing a plain array (the only shape `CartController` consumes) decodes to the identical array, verified by locally running the fixed file against a `base64_encode(serialize(['items' => [...], 'coupon' => ...]))` payload and getting back the same array structure.

For a malicious payload containing a serialized object, the return value changes from a fully-constructed, magic-method-invoked object of the attacker's chosen class to a `__PHP_Incomplete_Class` placeholder holding the same public properties but with no code executed during construction - verified locally: a serialized object whose class defines `__wakeup()` no longer triggers that method after the fix, whereas it did before. `CartController::restore()`'s `$cart['items'] ?? []` / `$cart['coupon'] ?? null` access is unaffected by this since it never relied on the decoded value being a specific object type.

The `base64_decode(..., true)` failure path (`return ['items' => []]`) is untouched.

## Verification

Ran `php -l` (PHP 8.5.8 CLI, locally installed) against the fixed file in a scratch copy outside the case directory: "No syntax errors detected". Also executed the fixed file directly: a serialized-array cookie payload round-trips to the identical array, and a serialized-object payload with a `__wakeup()` method no longer invokes it, confirming the fix both preserves legitimate behavior and closes the magic-method vector.
