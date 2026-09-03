## Verdict

Exploitable. The `unserialize()` function at line 21 deserializes user-controlled cookie data without restrictions, allowing instantiation of arbitrary classes and execution of magic methods (`__wakeup()`, `__destruct()`, `__toString()`), enabling remote code execution via gadget chains.

## Source

`$_COOKIE['cart_state']` - untrusted cookie data supplied by the client.

## Fix

**Vulnerable code (line 21):**
```php
$cart = unserialize($rawCookie);
```

**Fixed code:**
```php
$cart = unserialize($rawCookie, ['allowed_classes' => false]);
```

Alternatively, for complete elimination of deserialization risks, replace with JSON:
```php
$decoded = json_decode($rawCookie, associative: true);
if (is_array($decoded)) {
    $cart = new ShoppingCart();
    $cart->items = $decoded['items'] ?? [];
    $cart->couponCode = $decoded['couponCode'] ?? '';
} else {
    $cart = new ShoppingCart();
}
```

## Explanation

The primary fix adds the `['allowed_classes' => false]` option (PHP 7.0+), which prevents object instantiation during deserialization. Any serialized objects in the payload become `__PHP_Incomplete_Class` instances instead, blocking magic method execution and eliminating gadget chain exploitation. The existing `instanceof` type check then safely validates the result and returns a new empty cart if the deserialized value is not a valid ShoppingCart, maintaining the application's safety contract.

The alternative JSON-based fix provides stronger guarantees by eliminating the use of `unserialize()` entirely. It trades the existing binary serialization format for JSON, requiring that any code writing the cookie also move to `json_encode()`. This approach removes the entire deserialization attack surface and is preferred when producers of the value can migrate together.

## Behaviour changes

**Primary fix (`allowed_classes => false`):**
- Existing serialized ShoppingCart objects in cookies will deserialize as `__PHP_Incomplete_Class` instances instead of ShoppingCart objects
- The `instanceof` check will fail, causing the function to return a new empty ShoppingCart
- Users will lose their cart state on the first request after deployment, but the application remains safe
- Future requests storing carts must ensure they store data in a safe format (JSON recommended)

**Alternative fix (JSON-based):**
- Existing serialized cookies will fail to deserialize (json_decode returns null for serialized data)
- The function returns a new empty ShoppingCart, consistent with the safe-default pattern
- Requires coordinated deployment: all code writing `$_COOKIE['cart_state']` must change to `json_encode()` simultaneously
- No magic method risks; complete elimination of the deserialization attack surface
- Enables schema validation and structured data handling in the future
