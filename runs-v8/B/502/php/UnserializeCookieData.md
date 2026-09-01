## Verdict

Exploitable. The attacker-controlled cookie `cart_state` is directly passed to `unserialize()` without integrity checks or class restrictions, allowing instantiation of arbitrary classes via gadget chains or magic methods.

## Source

Line 18-21: Cookie data `$_COOKIE['cart_state']` flows directly to `unserialize()` without validation.

```php
$rawCookie = $_COOKIE['cart_state'];
$cart = unserialize($rawCookie);
```

## Fix

**Vulnerable Code:**
```php
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];

    // VULNERABLE: Deserialization of untrusted cookie data
    $cart = unserialize($rawCookie);

    if (!$cart instanceof ShoppingCart) {
        return new ShoppingCart();
    }

    return $cart;
}
```

**Fixed Code:**
```php
function restoreCartFromCookie(): ShoppingCart
{
    if (!isset($_COOKIE['cart_state'])) {
        return new ShoppingCart();
    }

    $rawCookie = $_COOKIE['cart_state'];

    // Use json_decode() instead of unserialize() for untrusted data
    $data = json_decode($rawCookie, associative: true);
    
    if (!is_array($data)) {
        return new ShoppingCart();
    }

    $cart = new ShoppingCart();
    
    // Explicitly reconstruct the object with validated data
    if (isset($data['items']) && is_array($data['items'])) {
        $cart->items = $data['items'];
    }
    if (isset($data['couponCode']) && is_string($data['couponCode'])) {
        $cart->couponCode = $data['couponCode'];
    }

    return $cart;
}
```

## Explanation

The fix replaces `unserialize()` with `json_decode()`, which safely parses JSON data as plain arrays and scalars without invoking object instantiation or magic methods. The original code's `instanceof` check after deserialization provided no protection because the damage occurs during instantiation—arbitrary classes and gadget chains execute `__wakeup()` and `__destruct()` methods at construction time. By using `json_decode()` with an associative array result, the code treats untrusted input as data, not executable objects. The cart object is then explicitly reconstructed by creating a fresh `ShoppingCart` instance and populating only the expected properties with validated types. This requires the cookie to be set with `json_encode()` on the sending request, but the receiver now safely processes untrusted cookies.

## Behaviour changes

- The cookie data must now be JSON-encoded instead of PHP-serialized. Any code that sets `$_COOKIE['cart_state']` must use `json_encode(['items' => ..., 'couponCode' => ...])` instead of `serialize($cart)`.
- JSON-decoded arrays are returned as stdClass objects or associative arrays (depending on the `associative` parameter), not as ShoppingCart instances. The fix manually reconstructs a ShoppingCart object, so the return type contract is preserved.
- Type validation is explicit: array elements and couponCode are checked before assignment, so invalid or missing fields are silently ignored rather than causing deserialization errors.
- JSON cannot serialize closures, resources, or complex objects. If the cart's items or couponCode fields contain these types, the application logic must serialize them separately or use a different data format; JSON alone cannot express them.
