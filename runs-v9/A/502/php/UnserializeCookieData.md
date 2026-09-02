## Verdict

Confirmed. `unserialize()` is called directly on `$_COOKIE['cart_state']`, an attacker-controlled value (cookies are fully client-writable). PHP's `unserialize()` will instantiate arbitrary classes present in the application (and any autoloadable classes) and invoke their magic methods (`__wakeup`, `__destruct`, `__toString`, etc.) during and after deserialization. This is the classic PHP object-injection / property-oriented-programming (POP chain) primitive, and can lead to remote code execution, arbitrary file writes/deletes, or SQL injection depending on what "gadget" classes are reachable in the app or its dependencies (a common one is the `Guzzle`/`Monolog`/framework gadget chains, but even project-only classes can be abused). The `instanceof ShoppingCart` check happens only *after* unserialize has already run, so it does not prevent the attack - by then any gadget's constructor/wakeup/destruct side effects have already executed.

## Source

`$_COOKIE['cart_state']` (line 18, read into `$rawCookie`) - a client-controlled HTTP cookie value, flowing unmodified into `unserialize()` at line 21.

## Fix

Replace PHP's native `unserialize()` format with a data-only format (JSON) and manually rebuild the trusted object, rather than letting the deserializer instantiate arbitrary classes for you:

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

    // Decode as plain JSON data - no class instantiation, no magic methods.
    $decoded = json_decode($rawCookie, true);

    if (!is_array($decoded)) {
        return new ShoppingCart();
    }

    $cart = new ShoppingCart();

    if (isset($decoded['items']) && is_array($decoded['items'])) {
        $cart->items = $decoded['items'];
    }

    if (isset($decoded['couponCode']) && is_string($decoded['couponCode'])) {
        $cart->couponCode = $decoded['couponCode'];
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

The corresponding write side (wherever `cart_state` is set) must be updated to match, replacing `serialize($cart)` with `json_encode(['items' => $cart->items, 'couponCode' => $cart->couponCode])` so the two sides stay in sync.

If the serialized format cannot be changed (e.g. for backward compatibility with existing cookies during a migration window), the minimum safe fix is to pass `unserialize($rawCookie, ['allowed_classes' => false])`, which decodes scalars/arrays but converts any embedded object into an inert `__PHP_Incomplete_Class` instead of instantiating it - closing the code-execution primitive while keeping the same wire format. `['allowed_classes' => ['ShoppingCart']]` is a narrower alternative if `ShoppingCart` itself must be reconstructed as a real instance, but only list classes that are provably safe to instantiate with attacker-controlled property values (no dangerous constructor, `__wakeup`, or `__destruct` logic). JSON is still the preferred fix since it removes the class-instantiation surface entirely rather than allowlisting it.

## Explanation

`unserialize()` on untrusted input is dangerous because PHP's serialization format encodes not just data but *type* - `O:8:"SomeClass":...` tells the engine to instantiate `SomeClass` and populate its properties directly, bypassing the constructor's normal validation logic, and then to call `__wakeup()` (and later `__destruct()`) on it. An attacker who controls the serialized string can name any class visible to the application's autoloader, not just `ShoppingCart`, and set its properties to arbitrary values. If any class reachable in the app or its Composer dependencies has a magic method that performs a dangerous operation (file I/O, a query, a `call_user_func` on an attacker-supplied value, etc.), the attacker can chain those side effects into code execution - this is a well-documented PHP exploitation pattern (PHPGGC catalogues public gadget chains for common frameworks/libraries).

The `if (!$cart instanceof ShoppingCart)` check in the original code is a red herring from a security standpoint: it filters what gets *returned* from the function, but by the time that check runs, `unserialize()` has already fully constructed whatever object the payload specified and already fired its magic methods. Validating the type after the fact cannot undo those side effects.

JSON decoding is safe here because `json_decode()` never instantiates PHP classes or invokes magic methods - it only ever produces scalars, arrays, and (with the associative flag) nested arrays, all inert data. Rebuilding the `ShoppingCart` object manually from validated, type-checked fields means the attacker can only influence the *values* stored in `items`/`couponCode`, never the *type* of object created or which code paths execute during construction - eliminating the object-injection primitive entirely rather than trying to filter it.
