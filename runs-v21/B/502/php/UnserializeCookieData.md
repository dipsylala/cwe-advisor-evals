## Verdict

The finding is confirmed. The `unserialize()` call on line 21 deserializes untrusted cookie data without class restrictions, enabling instantiation of arbitrary classes and execution of magic methods.

## Source

`$_COOKIE['cart_state']` (line 18) - attacker-controlled cookie value

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

    // Deserialize with strict class allowlist to prevent gadget chain instantiation
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

The fix adds the `['allowed_classes' => [ShoppingCart::class]]` parameter to `unserialize()`. This restricts object instantiation to the `ShoppingCart` class only, preventing an attacker from crafting a malicious serialized payload that instantiates arbitrary classes with magic methods (`__wakeup`, `__destruct`, `__toString`). The fix preserves the existing wire format (PHP serialization in cookies), maintains the function's return contract, and keeps the existing validation logic intact. Cookies already containing legitimate `ShoppingCart` serializations continue to deserialize correctly.

## Behaviour changes

The function now rejects cookies containing serialized objects of any class other than `ShoppingCart`. Since the code already validates `instanceof ShoppingCart` and returns a fresh empty cart if the check fails (lines 23-25), this change is consistent with existing behavior and produces no breaking changes for legitimate callers.

