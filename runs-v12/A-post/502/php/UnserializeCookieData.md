## Verdict
CWE-502 vulnerability confirmed. The code deserializes untrusted cookie data using `unserialize()`, creating a PHP Object Injection attack vector.

## Source
Line 21 in `restoreCartFromCookie()` calls `unserialize()` on `$_COOKIE['cart_state']`, which is user-controlled data. Attackers can craft malicious serialized objects to instantiate arbitrary classes and execute code through `__wakeup()` or `__destruct()` magic methods.

## Fix
Replace `unserialize()` with `json_decode()` and serialize data as JSON instead of PHP's native format:

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

    // Deserialize using JSON instead of unserialize()
    $data = json_decode($rawCookie, true);
    
    if (!is_array($data)) {
        return new ShoppingCart();
    }

    $cart = new ShoppingCart();
    
    // Reconstruct from trusted array data only
    if (isset($data['items']) && is_array($data['items'])) {
        $cart->items = $data['items'];
    }
    if (isset($data['couponCode']) && is_string($data['couponCode'])) {
        $cart->couponCode = $data['couponCode'];
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation
PHP's `unserialize()` function is unsafe with untrusted input because it can reconstruct arbitrary objects and invoke their magic methods, leading to arbitrary code execution through PHP Object Injection chains. JSON is a data-only format that cannot contain code; using `json_decode()` eliminates this attack vector entirely.

The fix deserializes to a plain array, validates the array structure, and manually reconstructs the `ShoppingCart` object from trusted array elements. This ensures only expected data types are accepted and no unexpected object instantiation occurs. When storing cart state in cookies, use `json_encode()` instead of `serialize()` to ensure data is always JSON.
