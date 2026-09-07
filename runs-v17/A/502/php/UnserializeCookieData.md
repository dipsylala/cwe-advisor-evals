## Verdict
Real issue confirmed. The code deserializes untrusted cookie data without restrictions, allowing arbitrary object instantiation and potential code execution through object injection attacks.

## Source
E:/Github/cwe-advisor/evals/cases/502/php/UnserializeCookieData/UnserializeCookieData.php, line 21:
```php
$cart = unserialize($rawCookie);
```

The vulnerability: `$_COOKIE['cart_state']` is attacker-controlled data that is passed directly to `unserialize()` without restrictions. An attacker can craft a malicious serialized payload containing any class available in the application or loaded libraries, triggering property injection or magic method execution (__wakeup, __destruct) to achieve arbitrary code execution.

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

    // Safely unserialize with allowed_classes restriction to prevent arbitrary object instantiation
    $cart = unserialize($rawCookie, ['allowed_classes' => ['ShoppingCart']]);

    if (!$cart instanceof ShoppingCart) {
        return new ShoppingCart();
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation
The fix adds the `allowed_classes` parameter to `unserialize()` (available since PHP 7.0), restricting deserialization to only the ShoppingCart class. This prevents:

1. **Arbitrary class instantiation**: Attackers cannot inject objects of other classes that might have dangerous magic methods or gadget chains.
2. **Object injection attacks**: Even if malicious serialized data is crafted, only ShoppingCart instances can be created; anything else will fail deserialization and return false, triggering the fallback to a fresh cart.
3. **Magic method exploitation**: Restricting the allowed classes prevents `__wakeup()`, `__destruct()`, and other magic methods in arbitrary classes from executing during deserialization.

The subsequent `instanceof` check (lines 23-25) remains as a safety net: if deserialization fails or produces an unexpected type, the code returns a fresh cart. The fix maintains backward compatibility and the same control flow while closing the deserialization vulnerability.
