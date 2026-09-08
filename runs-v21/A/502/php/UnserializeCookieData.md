## Verdict

Real. Line 21 passes untrusted cookie data directly to `unserialize()`, allowing an attacker to instantiate arbitrary objects. PHP deserialization can trigger dangerous methods during object construction, leading to arbitrary code execution via gadget chains.

## Source

```php
$rawCookie = $_COOKIE['cart_state'];
$cart = unserialize($rawCookie);
```

The `$_COOKIE` superglobal is attacker-controlled. `unserialize()` reconstructs arbitrary PHP objects, which may trigger `__wakeup()`, `__destruct()`, or similar magic methods during deserialization.

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

    // Use json_decode instead of unserialize to avoid CWE-502
    $data = json_decode($rawCookie, true);

    if (!is_array($data)) {
        return new ShoppingCart();
    }

    $cart = new ShoppingCart();
    $cart->items = is_array($data['items'] ?? null) ? $data['items'] : [];
    $cart->couponCode = is_string($data['couponCode'] ?? null) ? $data['couponCode'] : '';

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation

The vulnerability exists because `unserialize()` reconstructs arbitrary PHP objects from a user-controlled cookie value. Attackers can craft malicious serialized payloads that instantiate dangerous objects, triggering magic methods (`__wakeup()`, `__destruct()`, etc.) that may lead to code execution if vulnerable gadget chains exist in loaded libraries.

The fix replaces `unserialize()` with `json_decode()`, which only produces primitive types and arrays. The deserialized data is then used to manually reconstruct a `ShoppingCart` object with type validation on each field:
- `$data['items']` must be an array, defaulting to an empty array if absent or invalid
- `$data['couponCode']` must be a string, defaulting to an empty string if absent or invalid

This eliminates the gadget chain attack surface while preserving the application's functionality. JSON serialization also has better interoperability with modern systems and does not execute arbitrary code during deserialization.

