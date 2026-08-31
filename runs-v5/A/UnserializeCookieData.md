## Verdict
Confirmed. `unserialize()` is called directly on `$_COOKIE['cart_state']`, which is fully attacker-controlled (a client can set any cookie value). PHP's native `unserialize()` will instantiate arbitrary classes from the serialized string and invoke their magic methods (`__wakeup`, `__destruct`, `__toString`, etc.) during and after deserialization. If any class reachable via autoloading in this application has a magic method with a dangerous side effect (file write, command execution, SQL query, object-injection gadget chain), an attacker can trigger it purely by crafting a cookie value. This is a textbook CWE-502 sink.

## Source
`$_COOKIE['cart_state']` (line 18/21) - a raw HTTP cookie value, fully controlled by the client and never validated or restricted before being handed to `unserialize()`.

## Fix
Replace the PHP-native serialization format with JSON, which has no executable/object-instantiation semantics, and manually reconstruct the `ShoppingCart` value object from the decoded array:

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

    // Decode as JSON, not PHP serialization: JSON has no class-instantiation
    // or magic-method semantics, so a crafted cookie cannot execute a
    // deserialization gadget chain.
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

Whatever code path *writes* `cart_state` (not shown in this file) must be updated to match: emit the cookie with `json_encode(['items' => $cart->items, 'couponCode' => $cart->couponCode])` instead of PHP's `serialize()`, so the two sides stay in sync.

If switching the wire format is not viable and `unserialize()` must be kept, the minimum mitigation is to pass the `allowed_classes` option explicitly: `unserialize($rawCookie, ['allowed_classes' => [ShoppingCart::class]])`. This still lets PHP construct a `ShoppingCart` (and does not run its constructor, only sets its declared properties) but refuses to instantiate any other class, closing off gadget-chain exploitation via unrelated classes. Never call `unserialize()` on untrusted input with the default `allowed_classes` behavior (which permits any class) or explicitly set to `true`.

## Explanation
`unserialize()` walks the byte string and, for any `O:<len>:"<ClassName>":...` segment, instantiates `ClassName` and populates its properties directly from attacker-supplied data, then calls `__wakeup()` (or `__unserialize()` on PHP 7.4+) if the class defines one - and later, `__destruct()` when the object is garbage-collected. None of this requires the class to be "expected" by this function: any class already loaded or autoloadable in the application is eligible. A cookie is trivially attacker-writable (via browser dev tools, `curl`, or a set-cookie response from an attacker-controlled subdomain sharing the parent domain), so this is remote, unauthenticated, attacker-controlled input reaching a dangerous sink with no validation in between.

The `instanceof ShoppingCart` check after the call is not a mitigation: by the time it runs, `unserialize()` has already instantiated whatever class the payload named and already invoked that class's magic methods. The check only decides whether the *return value* of this function is trusted, not whether the deserialization itself was safe. Switching to `json_decode()` removes the vulnerability class entirely, because JSON decoding produces only PHP scalars, arrays, and (with the `true` associative flag used above) never objects - there is no mechanism by which a JSON payload can cause a class to be instantiated or a magic method to run.
