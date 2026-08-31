## Verdict

Confirmed CWE-502: Deserialization of Untrusted Data. The cookie `$_COOKIE['cart_state']` is untrusted user input deserialized directly via `unserialize()` without validation, enabling arbitrary class instantiation and magic method invocation.

## Source

`$_COOKIE['cart_state']` (line 18) flows directly to `unserialize()` on line 21 with no integrity check or class whitelist applied.

## Fix

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

    // Replace unsafe unserialize() with json_decode()
    $decodedData = json_decode($rawCookie, associative: true);
    
    if (!is_array($decodedData)) {
        return new ShoppingCart();
    }

    // Reconstruct ShoppingCart from trusted JSON structure
    $cart = new ShoppingCart();
    if (isset($decodedData['items']) && is_array($decodedData['items'])) {
        $cart->items = $decodedData['items'];
    }
    if (isset($decodedData['couponCode']) && is_string($decodedData['couponCode'])) {
        $cart->couponCode = $decodedData['couponCode'];
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation

`unserialize()` on untrusted data can instantiate arbitrary classes and invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution through gadget chains. The fix replaces `unserialize()` with `json_decode()`, which is a safe data format incapable of executing code. The decoded data is then explicitly reconstructed into a ShoppingCart object with type validation on each property, ensuring only expected data is accepted and the application logic remains intact.

## Behaviour changes

- Cookie format changes from serialized PHP objects to JSON (downstream cookie-setting code must be updated to use `json_encode()`)
- Malformed JSON or missing fields now return an empty cart rather than potentially deserializing malicious objects
- Type validation is explicit per property rather than relying on `instanceof` after deserialization
