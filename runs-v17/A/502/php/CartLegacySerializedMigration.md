## Verdict
CWE-502 confirmed. The `unserialize()` call on line 16 deserializes untrusted data from the database without restricting object instantiation, allowing arbitrary code execution through gadget chains.

## Source
`CartRepository.php:16` — `unserialize($row['cart_data'])`

The cart data is retrieved from a database and passed directly to `unserialize()` without any safeguards.

## Fix

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
The fix adds the `allowed_classes` option set to `false` to the `unserialize()` call. This option, introduced in PHP 7.0, restricts deserialization to scalar types (strings, integers, floats, booleans, null, and arrays of scalars) while preventing instantiation of arbitrary objects. This closes the gadget chain attack vector while preserving the existing serialized format and maintaining backward compatibility with existing cart data stored in the database.
