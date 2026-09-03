## Verdict
Confirmed: CWE-502 (Deserialization of Untrusted Data). The `unserialize()` function deserializes user-supplied cookie data without validation, enabling PHP Object Injection attacks through crafted serialized objects containing instances of classes with dangerous magic methods.

## Source
Line 21 of UnserializeCookieData.php:
```php
$cart = unserialize($rawCookie);
```

The source is `$_COOKIE['cart_state']` on line 18, which flows untrusted from the client to the unsafe deserialization sink.

## Fix
Replace `unserialize()` with JSON-based deserialization:

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

    // Safely decode JSON-encoded cookie data
    $data = json_decode($rawCookie, associative: true);
    
    if (!is_array($data)) {
        return new ShoppingCart();
    }

    $cart = new ShoppingCart();
    
    // Validate and assign items array
    if (isset($data['items']) && is_array($data['items'])) {
        $cart->items = $data['items'];
    }
    
    // Validate and assign coupon code string
    if (isset($data['couponCode']) && is_string($data['couponCode'])) {
        $cart->couponCode = $data['couponCode'];
    }

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation
The vulnerability stems from calling `unserialize()` on untrusted cookie data. PHP's `unserialize()` reconstructs full object instances, allowing an attacker to instantiate arbitrary classes and trigger magic methods like `__wakeup()` and `__destruct()`. This enables arbitrary code execution through gadget chain attacks if suitable classes exist in the application.

The fix replaces native PHP serialization with JSON:

1. **Use `json_decode()` instead of `unserialize()`**: JSON deserialization creates only primitive arrays and strings, never arbitrary objects. This eliminates object injection vectors entirely.

2. **Validate array structure**: Check that `json_decode()` returns an array and that each field has the expected type before assignment.

3. **Manually construct the object**: Build the `ShoppingCart` from validated data, ensuring type safety. The instance is created under application control, not from untrusted serialized data.

4. **Validate field types**: Before assigning decoded values, confirm they match the expected type (`is_array()` for `items`, `is_string()` for `couponCode`). This prevents type confusion attacks.

The cookie should be set by the application using `json_encode()` when serializing the cart, ensuring the server controls both encoding and decoding, and the data stream contains only safe primitives.
