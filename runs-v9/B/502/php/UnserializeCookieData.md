## Verdict

CWE-502 (Deserialization of Untrusted Data) - **exploitable**. Confidence: high.

`unserialize()` at `UnserializeCookieData.php:21` is called on a raw, unauthenticated cookie value with no `allowed_classes` restriction. Any class autoloadable by the application can be instantiated, and PHP invokes magic methods (`__wakeup()`, `__destruct()`, `__toString()`) as part of that instantiation - before the code's own `instanceof ShoppingCart` check ever runs. A gadget chain built from classes already present in the application (or its dependencies) can achieve code execution or object injection purely by crafting the cookie value; no signature or integrity check on the cookie is present anywhere in the file to prevent this.

## Source

- **Source:** `$_COOKIE['cart_state']` (line 14/18) - fully attacker-controlled; a client can set arbitrary cookie content on any request.
- **Flow:** `$_COOKIE['cart_state']` -> `$rawCookie` (line 18) -> `unserialize($rawCookie)` (line 21, sink).
- **Sink contract:** `unserialize()` returns the reconstructed value on success, or `false` with an `E_WARNING` on malformed/incomplete input. The existing `!$cart instanceof ShoppingCart` check (line 23) already treats a `false` return, a scalar, an array, or an unexpected object type as "invalid" and falls back to `new ShoppingCart()`. That check runs *after* deserialization completes, so it cannot prevent code that already ran via magic methods during unserialization - it only filters the resulting value.

## Fix

Vulnerable code:

```php
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
$cart = unserialize($rawCookie);
```

Fixed code:

```php
// Restrict unserialize() to the one class this cookie is expected to carry.
// Any other class is returned as an inert __PHP_Incomplete_Class instead of
// being instantiated, so no magic method (__wakeup/__destruct/__toString) runs.
$cart = unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]]);
```

## Explanation

The one-file scope available here shows only the read side of the cookie round-trip (no `serialize()` call is present to redesign the write side), so the applicable fix from the PHP guidance is the documented last-resort mitigation: pass `allowed_classes` to `unserialize()` and whitelist only the class the application actually expects, `ShoppingCart`. With this option set, PHP instantiates `ShoppingCart` normally when the payload matches, but converts any other serialized class into a `__PHP_Incomplete_Class` object without invoking its constructor or any magic method - which is precisely where gadget-chain code execution occurs. The existing `!$cart instanceof ShoppingCart` check then rejects that incomplete object exactly as it already rejects `false`/array/scalar results, so no new code path is needed downstream. This closes the arbitrary-class-instantiation vector; it does not add integrity verification (e.g. an HMAC over the cookie), since no signing mechanism exists elsewhere in the provided code to build on.

## Behaviour changes

- **Added argument:** `unserialize()` now receives an explicit `['allowed_classes' => [ShoppingCart::class]]` options array instead of running with PHP's default (which permits every class). This is the fix itself, not a side effect.
- **Non-`ShoppingCart` objects in the cookie:** previously such a serialized object would be fully instantiated (magic methods executing as a side effect) before being discarded by the `instanceof` check; now it arrives as a `__PHP_Incomplete_Class` value with no method invocation, and is discarded by the same, already-present `instanceof` check. Net observable behavior for legitimate carts (serialized `ShoppingCart` payloads) is unchanged; malicious or malformed class payloads now fail inertly instead of executing attacker logic during deserialization.
- **No other change:** return value contract, control flow, and the fallback-to-`new ShoppingCart()` behavior are all preserved as in the original.
