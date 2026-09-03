## Verdict

**Vulnerable**: The code deserializes untrusted cookie data directly with `unserialize()` without integrity checks or class restrictions, allowing attackers to instantiate arbitrary classes via gadget chains (CWE-502).

## Source

**File**: `UnserializeCookieData.php` line 21  
**Vulnerable code**: `$cart = unserialize($rawCookie);`

**Data flow**:
- Source: `$_COOKIE['cart_state']` (untrusted user-controlled data)
- Intermediate: Stored in `$rawCookie` variable
- Sink: `unserialize($rawCookie)` on line 21

**Sink contract**:
- Returns: An object of indeterminate type (though the code expects `ShoppingCart`)
- The `allowed_classes` parameter is not supplied, defaulting to `true`, which permits instantiation of any class
- Failure behavior: Returns `false` on error; the code checks `instanceof ShoppingCart` to detect this case

## Fix

Replace `unserialize()` with `json_decode()` and refactor the deserialization logic to safely construct a `ShoppingCart` object from JSON data:

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

    // Decode JSON instead of using unserialize()
    $data = json_decode($rawCookie, associative: true);
    
    if ($data === null || !is_array($data)) {
        return new ShoppingCart();
    }

    // Safely reconstruct the object with validated data
    $cart = new ShoppingCart();
    $cart->items = is_array($data['items'] ?? null) ? $data['items'] : [];
    $cart->couponCode = is_string($data['couponCode'] ?? null) ? $data['couponCode'] : '';

    return $cart;
}

$cart = restoreCartFromCookie();
echo "Items in cart: " . count($cart->items) . "\n";
```

## Explanation

The original code uses PHP's `unserialize()` function to reconstruct a `ShoppingCart` object from a cookie value. This is unsafe because:

1. **Arbitrary class instantiation**: Without the `allowed_classes` parameter, `unserialize()` can instantiate any class present in the PHP runtime, including framework or library classes with exploitable magic methods (`__wakeup()`, `__destruct()`, `__toString()`).

2. **Gadget chain exploitation**: Attackers can craft a serialized payload that chains together multiple objects to achieve remote code execution (RCE) via property-oriented programming.

3. **No integrity verification**: The cookie is read directly from user input with no HMAC or other integrity check, making it trivial for attackers to manipulate.

The fix replaces `unserialize()` with `json_decode()`, which safely parses JSON data without instantiating arbitrary classes. The deserialized data is explicitly validated, type-checked, and used to manually construct a `ShoppingCart` object. This ensures:

- Only data is processed, no code execution
- Type safety: array and string fields are verified before assignment
- Simple, predictable behavior with no magic method invocations
- Full compatibility with secure client-side JSON serialization

When this code is integrated, ensure that code setting the cookie serializes the `ShoppingCart` to JSON (e.g., `json_encode(['items' => $cart->items, 'couponCode' => $cart->couponCode])`), not to PHP's serialized format.

## Behaviour changes

- The cookie must now contain JSON instead of PHP-serialized data. Any existing cookies in this format will fail to decode and return a fresh `ShoppingCart()`.
- Field validation is stricter: extra fields in the JSON are ignored, missing fields default to empty array or empty string.
- No magic methods are invoked during reconstruction (intentional security hardening).
- Error handling is identical: malformed data returns a fresh empty cart, matching the original `instanceof` check logic.
