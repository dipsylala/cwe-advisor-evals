## Verdict

Exploitable

## Source

**Source**: Untrusted cookie input `$cookies['cart']` passed to `CartCookie::decode()` in CartController.restore() at line 9 of CartController.php.

**Sink**: `unserialize($payload)` at line 12 of CartCookie.php, called without object instantiation restrictions.

**Data flow**: 
1. CartController.restore() receives `$cookies` array (attacker-controlled HTTP cookies)
2. Extracts `$encoded = $cookies['cart'] ?? ''` (line 9)
3. Calls `CartCookie::decode($encoded)` (line 10)
4. CartCookie.decode() performs `base64_decode($encoded, true)` (line 7)
5. Result passed directly to `unserialize($payload)` (line 12) with no restrictions

## Fix

**Vulnerable code:**
```php
public static function decode(string $encoded): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false) {
        return ['items' => []];
    }

    return unserialize($payload);  // Line 12: No object instantiation restrictions
}
```

**Fixed code:**
```php
public static function decode(string $encoded): mixed
{
    $payload = base64_decode($encoded, true);
    if ($payload === false) {
        return ['items' => []];
    }

    return unserialize($payload, ['allowed_classes' => false]);
}
```

## Explanation

The fix adds the `['allowed_classes' => false]` option to the `unserialize()` call. This parameter, introduced in PHP 7.0, prevents the instantiation of any objects during deserialization. Any serialized objects in the payload will instead be converted to `__PHP_Incomplete_Class` instances, preventing the execution of magic methods (`__wakeup()`, `__destruct()`, `__toString()`) that attackers exploit through gadget chains. The cart data structure contains only arrays and scalars (items and coupon fields), so this change maintains full backward compatibility with existing serialized data while eliminating the object instantiation vector. The wire format remains unchanged, so no changes to producers are required.

## Behaviour changes

**Argument change**: The second parameter `options` is now explicitly passed to `unserialize()`, whereas it was previously left at its default. The PHP 7.0+ default allows all classes; the new explicit value restricts class instantiation entirely.

**Object handling**: Any serialized objects in the payload will now deserialize to `__PHP_Incomplete_Class` instances rather than their original classes. For the cart structure (arrays with 'items' and 'coupon' keys), this has no impact since the payload contains no objects. If unexpected object data appears in a cookie (indicating either corruption or an attack), the partially-deserialized incomplete object will be cast to its expected array structure by the subsequent `['items' => $cart['items'] ?? []]` logic in CartController.restore(), maintaining defensive handling.

**Return behavior**: The return type remains `mixed` and the return value shape is unchanged for legitimate payloads. Error behavior is preserved: false from base64_decode still returns the empty cart array.
