## Verdict

Exploitable. The code deserializes untrusted cookie data without integrity checks or class restrictions, enabling arbitrary code execution via gadget chains or magic method invocation.

## Source

`$_COOKIE['cart_state']` (line 18) — attacker-controlled cookie data flows directly to the sink.

## Fix

**Vulnerable code:**
```php
$rawCookie = $_COOKIE['cart_state'];

// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
$cart = unserialize($rawCookie);
```

**Fixed code:**
```php
$rawCookie = $_COOKIE['cart_state'];

// Replace unserialize() with json_decode() to prevent arbitrary class instantiation
$cartData = json_decode($rawCookie, true);

if (!is_array($cartData)) {
    return new ShoppingCart();
}

$cart = new ShoppingCart();
if (isset($cartData['items']) && is_array($cartData['items'])) {
    $cart->items = $cartData['items'];
}
if (isset($cartData['couponCode']) && is_string($cartData['couponCode'])) {
    $cart->couponCode = $cartData['couponCode'];
}
```

## Explanation

PHP's `unserialize()` can instantiate arbitrary classes and invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution through gadget chains. The original code passes untrusted cookie data directly to `unserialize()` with no integrity check or class whitelist, making the application vulnerable.

The fix replaces `unserialize()` with `json_decode()`, which treats input as inert data and does not instantiate arbitrary classes. The decoded associative array is then used to safely reconstruct the ShoppingCart object with explicit type validation for each property. This eliminates the deserialization attack surface while preserving the functionality of restoring cart state.

## Behaviour changes

- **Data format change**: The cookie storage format changes from PHP serialized format to JSON. Existing serialized cookies will fail to decode and return a new empty cart (consistent with the original fallback behaviour).
- **Type validation**: Properties are now validated as they are assigned (`is_array()` for items, `is_string()` for couponCode). Malformed or missing properties are silently skipped; the cart reconstructs with only valid data.
- **No magic method invocation**: `__wakeup()`, `__destruct()`, and `__toString()` methods on ShoppingCart or any other class are no longer executed during deserialization, closing the gadget chain vector.
