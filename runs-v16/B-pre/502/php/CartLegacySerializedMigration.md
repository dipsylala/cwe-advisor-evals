## Verdict

Exploitable

## Source

`$row['cart_data']` — untrusted serialized data retrieved from the database via SELECT query without integrity validation

## Fix

**Vulnerable code:**
```php
return unserialize($row['cart_data']);
```

**Fixed code:**
```php
return unserialize($row['cart_data'], ['allowed_classes' => false]);
```

## Explanation

The `unserialize()` call processes database-stored cart data without restricting object instantiation, allowing attackers to exploit arbitrary class instantiation and magic methods (`__wakeup()`, `__destruct()`, `__toString()`) via gadget chains or property-oriented programming. Adding the `['allowed_classes' => false]` option prevents all object construction during deserialization, converting any serialized objects in the payload to `__PHP_Incomplete_Class` instances so magic methods never execute. Since the function returns `array` type and the data represents a cart (expected to contain only arrays and scalars), this fix maintains the intended behavior for legitimate data-only payloads while closing the deserialization vulnerability vector.

## Behaviour changes

Objects within the serialized payload, if any exist, will be converted to `__PHP_Incomplete_Class` instances instead of their original classes. This prevents magic method execution and eliminates the gadget-chain attack surface. For data-only payloads (arrays and scalars), behavior is preserved; the function still returns the unserialized cart data structure as expected.
