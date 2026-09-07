## Verdict

Real issue, fix applied.

## Source

Attacker-controlled cookie `$_COOKIE['cart_state']` is deserialized at line 21 without restrictions on which classes can be instantiated, allowing arbitrary object construction and magic method invocation via gadget chains.

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

    // Deserialization restricted to ShoppingCart class only to prevent arbitrary code execution
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

CWE-502 occurs when `unserialize()` processes untrusted data without class restrictions, allowing instantiation of arbitrary classes and invocation of magic methods (`__wakeup()`, `__destruct()`, `__toString()`), which can lead to remote code execution via PHP object gadget chains.

The fix adds the `['allowed_classes' => [ShoppingCart::class]]` option to the `unserialize()` call, restricting deserialization to only the ShoppingCart class. This prevents gadget chain attacks while maintaining compatibility with legitimate serialized ShoppingCart objects from the cookie. Objects of classes not in the allowlist are converted to `__PHP_Incomplete_Class` instances, which fail the `instanceof ShoppingCart` check on line 23 and cause the function to return an empty cart instead.

PHP syntax validation: `php -l` passed with no errors.

## Behaviour changes

- **Legitimate input** (serialized ShoppingCart objects): Behavior unchanged. Objects are correctly deserialized and returned.
- **Malicious input** (serialized objects of other classes): Objects are not instantiated as their original class; they become `__PHP_Incomplete_Class` instances that fail the `instanceof ShoppingCart` check, causing the function to return an empty ShoppingCart instead of executing attacker-controlled code.
