## Verdict

Confirmed. `unserialize()` is called directly on `$_COOKIE['cart_state']`, which is fully attacker-controlled (a client can set any cookie value it likes). PHP's `unserialize()` will instantiate any class named in the serialized payload and invoke its magic methods (`__wakeup()`, `__destruct()`, `__toString()`, etc.) during and after construction. If any class reachable by the application's autoloader (including third-party/framework classes) has a magic method that performs a dangerous operation, an attacker can craft a serialized string that builds a property-object graph (a "POP gadget chain") to trigger arbitrary file writes, SSRF, or code execution - independent of the `instanceof ShoppingCart` check that runs only after deserialization has already happened.

## Source

`$_COOKIE['cart_state']` in `restoreCartFromCookie()` (line 18), flowing unmodified into `unserialize()` at line 21.

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

    // Only ShoppingCart is ever legitimately stored in this cookie. Restricting
    // allowed_classes prevents unserialize() from instantiating any other class,
    // which closes off PHP object-injection / POP gadget-chain attacks while still
    // supporting the existing cookie format.
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

The root cause is not `unserialize()` itself but that it is invoked with no restriction on which classes it is allowed to instantiate, over data the client fully controls. Passing the `allowed_classes` option restricts deserialization so that only instances of `ShoppingCart` are ever constructed; any other class name embedded in the payload causes `unserialize()` to produce an incomplete/non-instantiable object instead of invoking that class's constructor or magic methods, and the existing `instanceof ShoppingCart` guard then rejects it and falls back to a fresh cart. This keeps the cookie's existing serialized-object wire format intact (no migration of already-issued cookies is needed) while eliminating the ability to smuggle in and trigger arbitrary gadget classes. Reject-on-mismatch behavior for a tampered or malformed cookie is unchanged: the function still returns a new, empty `ShoppingCart` rather than throwing or exposing internal errors to the client.
