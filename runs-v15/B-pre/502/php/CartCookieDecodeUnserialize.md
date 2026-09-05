## Verdict

Exploitable. Untrusted cookie data is deserialized without object construction restrictions, allowing arbitrary class instantiation and magic method execution.

## Source

`CartController::restore()` line 9: `$cookies['cart']` — untrusted user-supplied cookie value.

## Fix

**Vulnerable code (CartCookie.php line 12):**
```php
return unserialize($payload);
```

**Fixed code:**
```php
return unserialize($payload, ['allowed_classes' => false]);
```

## Explanation

The payload contains data-only structures (arrays with 'items' and 'coupon' keys per CartController lines 13-14). Adding the `['allowed_classes' => false]` option to `unserialize()` prevents PHP from instantiating any objects during deserialization. Any serialized objects in the payload become inert `__PHP_Incomplete_Class` instances with no magic methods invoked, eliminating the gadget-chain and property-oriented-programming attack vectors. Existing array and scalar data decode normally, preserving the wire format and backward compatibility with already-serialized cookies.

## Behaviour changes

None. The option prevents object instantiation while preserving array/scalar decoding, maintaining the exact return contract: an array with optional 'items' and 'coupon' keys, or the empty-cart default on decode failure.
