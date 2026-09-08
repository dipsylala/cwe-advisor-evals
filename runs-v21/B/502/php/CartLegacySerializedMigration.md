## Verdict

Exploitable. The code deserializes database-stored data without restricting object instantiation, enabling arbitrary object construction via gadget chains or property-oriented programming attacks.

## Source

Line 16 in CartRepository.php. `$row['cart_data']` comes from a database query result (line 8-9, SELECT from carts table).

## Fix

The `unserialize()` call must restrict object instantiation. Since the return type is `array` and the payload contains only data structures (a cart), add the `allowed_classes` option set to `false` to prevent object reconstruction while preserving array/scalar deserialization.

### File: CartRepository.php

```php
<?php

class CartRepository
{
    public function loadCart(PDO $pdo, int $userId): array
    {
        $stmt = $pdo->prepare("SELECT cart_data FROM carts WHERE user_id = ?");
        $stmt->execute([$userId]);
        $row = $stmt->fetch();

        if ($row === false) {
            return [];
        }

        // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
        return unserialize($row['cart_data'], ['allowed_classes' => false]);
    }
}
```

## Explanation

The fix adds a second argument to `unserialize()`: `['allowed_classes' => false]`. This option prevents any object instantiation during deserialization, converting any serialized objects in the payload into incomplete-class stubs (`__PHP_Incomplete_Class` instances) that cannot invoke magic methods (`__wakeup()`, `__destruct()`, `__toString()`). Since the cart payload contains only arrays and scalars (the return type is `array`), the legitimate data deserializes normally. The wire format and storage contract remain unchanged, so existing serialized values in the database continue to work without migration. Magic-method gadget chains cannot execute because no real object is ever constructed.

## Behaviour changes

- Serialized objects in the payload become `__PHP_Incomplete_Class` instances instead of instantiated classes; this is safe and expected since the declared return type is `array` only.
- Performance is unchanged; no additional validation or format conversion occurs.
- Existing serialized data in the database continues to deserialize without migration.
