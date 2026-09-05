## Verdict

Confirmed. Line 21 deserializes untrusted cookie data without restricting object instantiation, enabling object injection attacks through malicious serialized payloads.

## Source

The vulnerability originates at line 18, where `$_COOKIE['cart_state']` is read directly from the HTTP request. Cookies are attacker-controlled and should be treated as untrusted input. The taint flows immediately to line 21, where `unserialize()` processes this untrusted data.

## Fix

Replace line 21:
```php
$cart = unserialize($rawCookie);
```

With:
```php
$cart = unserialize($rawCookie, ['allowed_classes' => false]);
```

This prevents `unserialize()` from instantiating objects of any class. Since the code already validates the result with `instanceof` on line 23, you may instead use a whitelist approach:
```php
$cart = unserialize($rawCookie, ['allowed_classes' => ['ShoppingCart']]);
```

The whitelist approach allows deserialization only for the `ShoppingCart` class and reconstructs it safely.

## Explanation

PHP's `unserialize()` function is vulnerable to object injection when processing untrusted data. An attacker can craft a malicious serialized payload that instantiates arbitrary classes with dangerous constructors or magic methods (`__wakeup`, `__destruct`), leading to arbitrary code execution, data corruption, or other attacks.

The `allowed_classes` option (available in PHP 7.0+) restricts which classes can be instantiated during deserialization. Setting it to `false` disables object instantiation entirely and only allows primitive types and arrays, which are safe. The whitelist variant `['allowed_classes' => ['ShoppingCart']]` permits only the specific class expected by the application.

This preserves the wire format (native serialization) while eliminating the gadget chain attack vector that makes deserialization of untrusted data dangerous.
