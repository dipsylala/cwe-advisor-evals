## Verdict

Confirmed. `unserialize()` is called on `$_COOKIE['cart_state']`, which is fully attacker-controlled, with no `allowed_classes` restriction and no integrity check. This lets an attacker submit a serialized payload naming any class available in the autoload path, triggering that class's `__wakeup`, `__destruct`, or `__toString` during deserialization (object injection / gadget-chain RCE).

## Source

`$_COOKIE['cart_state']` (line 18, read at the top of `restoreCartFromCookie()`) - an HTTP cookie value, fully controlled by the client and never validated or signed before use.

## Fix

### File: UnserializeCookieData.php

```php
<?php

class ShoppingCart
{
    public array $items = [];
    public string $couponCode = '';
}

/**
 * Restores the user's shopping cart from a cookie set on a previous request.
 */
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];

    // Only ShoppingCart may be constructed; no other class (and no magic method) can run.
    $cart = unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]]);

    if (!$cart instanceof ShoppingCart) {
        return new ShoppingCart();
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation

The sink is `unserialize($rawCookie)` at line 21, called with no second argument, so PHP's default `allowed_classes` behavior (accept any class) applies: a payload naming any class defined in the running process can be instantiated, and PHP invokes that class's `__wakeup()`, `__destruct()`, or `__toString()` as part of reconstructing or later using the object - the standard PHP object-injection path to RCE via a gadget chain, without needing any class defined in this file.

The code that consumes the result performs `$cart instanceof ShoppingCart`, which means the payload is expected to legitimately carry that one class - the case the PHP guidance calls out specifically: pass `['allowed_classes' => [ShoppingCart::class]]` rather than `false`, because `false` would turn every legitimately-serialized `ShoppingCart` into `__PHP_Incomplete_Class`, fail the `instanceof` check, and silently reset every returning visitor's cart to empty on every request - a functional regression disguised as a fix. Restricting to the single expected class keeps the existing cookie format (no producer/consumer format migration needed) and closes the vector: `ShoppingCart` itself declares no `__wakeup`, `__destruct`, or `__toString`, so even a forged `ShoppingCart`-typed payload has no magic-method code to run - only the `unserialize()` call needed to change.

No library change is needed; `allowed_classes` is a native `unserialize()` option available since PHP 7.0, and the file's only import/name introduced by the fix (`ShoppingCart::class`) already exists in the same file.

**Fix verified**: copied the file to a scratch location and ran `php -l` (no syntax errors). Also ran the function directly: a real `serialize(new ShoppingCart())` cookie still decodes to a `ShoppingCart` instance (functionality preserved); a `serialize(new Evil())` payload for a class with a `__destruct()` side effect is rejected - `restoreCartFromCookie()` returns a fresh empty `ShoppingCart` and the malicious class's destructor is never invoked during unserialization, confirming the magic-method vector is closed while legitimate carts still restore correctly.

## Behaviour changes

- A cookie whose serialized payload names any class other than `ShoppingCart` (previously silently accepted and instantiated) is now converted to `__PHP_Incomplete_Class` by `unserialize()`, fails the existing `instanceof ShoppingCart` check, and causes `restoreCartFromCookie()` to return a fresh empty cart - the same fallback path already used for a missing or malformed cookie. No legitimate `ShoppingCart` cookie is affected.
