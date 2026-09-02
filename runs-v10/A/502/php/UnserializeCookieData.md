## Verdict

Confirmed CWE-502: Deserialization of Untrusted Data. The `unserialize()` function on line 21 deserializes data directly from the `$_COOKIE` superglobal without validation, allowing object injection attacks.

## Source

```php
$rawCookie = $_COOKIE['cart_state'];
$cart = unserialize($rawCookie);  // Line 21 - unsafe deserialization of untrusted data
```

The vulnerability flows from the `$_COOKIE` superglobal (attacker-controlled) through `$rawCookie` to `unserialize()`, which can instantiate arbitrary objects and invoke magic methods if suitable gadget chains exist in the application or its dependencies.

## Fix

Replace `unserialize()` with `json_decode()` and encode the cart as JSON when storing it:

```php
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];
    
    // Use json_decode instead of unserialize
    $data = json_decode($rawCookie, associative: true);
    
    if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
        return new ShoppingCart();
    }
    
    $cart = new ShoppingCart();
    $cart->items = $data['items'] ?? [];
    $cart->couponCode = $data['couponCode'] ?? '';
    
    return $cart;
}
```

When setting the cookie, serialize with `json_encode()` instead:
```php
$cartData = json_encode([
    'items' => $cart->items,
    'couponCode' => $cart->couponCode
]);
setcookie('cart_state', $cartData, ...);
```

## Explanation

`unserialize()` is inherently unsafe for untrusted data because it can instantiate arbitrary classes and trigger magic methods (`__wakeup()`, `__destruct()`, etc.). If the application or any of its dependencies contains a vulnerable class chain (a gadget), an attacker can craft a serialized payload to achieve remote code execution.

`json_decode()` is safe by design: it only produces arrays or stdClass objects and never instantiates application-defined classes. It cannot trigger magic methods or execute code during deserialization. The fix manually reconstructs the `ShoppingCart` object from the decoded array, validating the structure in the process. JSON validation with `json_last_error()` ensures malformed data is rejected gracefully.

This approach eliminates the entire attack surface while preserving the functionality of persisting and restoring cart state.
