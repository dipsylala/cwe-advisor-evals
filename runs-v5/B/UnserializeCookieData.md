## Verdict

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `UnserializeCookieData.php`, line 21 (`$cart = unserialize($rawCookie);`)
- **verdict**: exploitable
- **confidence**: high

## Source

`$_COOKIE['cart_state']` (line 18, assigned to `$rawCookie`) - fully attacker-controlled: a client can set an arbitrary cookie value for `cart_state` on any request. It flows unmodified and unvalidated into `unserialize()` at line 21. No integrity check (HMAC or otherwise) and no `allowed_classes` restriction is applied, so `unserialize()` runs with its default behavior of permitting instantiation of any class defined or autoloadable in the application, including magic-method invocation (`__wakeup()`, `__destruct()`, `__toString()`) during object reconstruction. This is the standard PHP gadget-chain RCE/POP-chain vector for CWE-502.

The post-call check `!$cart instanceof ShoppingCart` happens only *after* deserialization has already run, so it cannot prevent any code execution that occurs during unserialization itself - it only discards the result afterward.

## Fix

Vulnerable code:

```php
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];

    // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
    $cart = unserialize($rawCookie);

    if (!$cart instanceof ShoppingCart) {
        return new ShoppingCart();
    }

    return $cart;
}
```

Fixed code:

```php
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];

    // Restrict unserialize() to instantiating only ShoppingCart - any other class
    // in the payload is returned as __PHP_Incomplete_Class instead of being
    // constructed, so no other class's constructor or magic methods ever run.
    $cart = unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]]);

    if (!$cart instanceof ShoppingCart) {
        return new ShoppingCart();
    }

    return $cart;
}
```

## Explanation

The fix keeps `unserialize()` but supplies the `allowed_classes` option (PHP 7.0+) restricted to `ShoppingCart`, the single class this code path expects to reconstruct. With that option set, the unserializer no longer autoloads or constructs any class named in the attacker-supplied payload other than `ShoppingCart`; every other class comes back as an inert `__PHP_Incomplete_Class` instance with no constructor, `__wakeup()`, `__destruct()`, or `__toString()` invoked on it. That removes the gadget-chain code-execution primitive at the sink while requiring no change outside this function. The knowledge base's primary recommendation is to replace `unserialize()` with `json_decode()` entirely; that was not applied here because the code that writes `cart_state` (the corresponding `serialize()` call) is outside this file's call chain, and switching the read side to JSON without a verified matching write side would silently break every legitimate cart-restore cookie already issued to users - so the whitelist restriction is applied as the guidance's documented "`unserialize()` unavoidable" fallback instead. No HMAC signature check was added for the same reason: nothing in the visible code establishes a signing key or verification convention to extend, and fabricating one would exceed this file's scope; a follow-up ticket to add cookie signing (and, ideally, migrate the format to JSON) once the write-side code is in scope is recommended.

## Behaviour changes

- `unserialize()` is now called with an `allowed_classes` restriction instead of PHP's default (all classes permitted). This is the fix itself, not a side effect.
- Any cookie payload that previously deserialized into a class other than `ShoppingCart` now comes back as `__PHP_Incomplete_Class` rather than the real object. The existing `!$cart instanceof ShoppingCart` check already discarded any non-`ShoppingCart` result and fell back to `new ShoppingCart()`, so observable behavior for that branch is unchanged.
- Legitimate `ShoppingCart` cookies deserialize identically to before, since `ShoppingCart` remains on the allow list.
- No HMAC integrity check was added and no serialization format change was made - both are noted as residual recommendations rather than applied, per the reasoning above.
- **assumptions**: assumed the code that sets the `cart_state` cookie (the `serialize()` write side) is outside the given single-file call chain and therefore out of scope for this fix; this is why the allowlist mitigation was chosen over the guidance's primary `json_decode()` replacement. Confidence is high on the vulnerability and the fix itself; this assumption does not affect exploitability of the finding, only the choice between two valid remediation options.
