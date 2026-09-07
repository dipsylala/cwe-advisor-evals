## Verdict
exploitable

## Source
`CartController::restore()` receives an untrusted HTTP cookie value (`$cookies['cart']`), which is base64-decoded and passed to `CartCookie::decode()`.

## Fix

**Vulnerable code (line 12):**
```php
return unserialize($payload);
```

**Fixed code:**
```php
return unserialize($payload, ['allowed_classes' => false]);
```

## Explanation
The vulnerability allows remote code execution through PHP object instantiation and magic method invocation during unserialization. The fix disables object reconstruction by passing `['allowed_classes' => false]` to `unserialize()`, which converts any objects in the serialized payload to `__PHP_Incomplete_Class` instances without triggering magic methods. This is safe here because `CartController::restore()` expects only scalar values and arrays (`items` array and `coupon` string/null), not objects. The wire format remains unchanged, so existing cookies already serialized with `serialize()` continue to decode correctly—only the deserialization safety is improved. This option has been available since PHP 7.0 and is part of the core language.

## Behaviour changes
None. The return value structure is preserved: arrays and scalars decode identically, and any embedded objects (which would exploit the original vulnerability) are neutralized to incomplete class instances. The contract with `CartController::restore()` remains intact, as it only accesses array keys (`['items']` and `['coupon']`), not object properties.
