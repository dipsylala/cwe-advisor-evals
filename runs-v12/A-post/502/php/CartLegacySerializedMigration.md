## Verdict

The finding is confirmed. Line 16 uses `unserialize()` on data from the database without restricting which classes may be deserialized, creating an object injection risk.

## Source

```php
return unserialize($row['cart_data']);
```

The `cart_data` column stored in the database contains serialized PHP objects. While the data originates from the database (not direct user input), an attacker who gains write access to the database can craft malicious serialized objects that exploit object injection vulnerabilities through magic methods like `__wakeup()` or `__destruct()`.

## Fix

Replace PHP's native serialization with JSON, which does not support arbitrary object instantiation:

```php
public function loadCart(PDO $pdo, int $userId): array
{
    $stmt = $pdo->prepare("SELECT cart_data FROM carts WHERE user_id = ?");
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    if ($row === false) {
        return [];
    }

    return json_decode($row['cart_data'], true) ?? [];
}
```

Update the corresponding save method to store data as JSON instead of serialized PHP:

```php
public function saveCart(PDO $pdo, int $userId, array $cartData): void
{
    $stmt = $pdo->prepare("UPDATE carts SET cart_data = ? WHERE user_id = ?");
    $stmt->execute([json_encode($cartData), $userId]);
}
```

During the migration period, add a schema migration to convert existing serialized data to JSON, or handle deserialization of legacy data with caution by using `unserialize()` with an empty `allowed_classes` array if the legacy data must remain in serialized form temporarily:

```php
return unserialize($row['cart_data'], ['allowed_classes' => false]);
```

## Explanation

`unserialize()` reconstructs PHP objects from their serialized form, which can trigger object instantiation and magic method execution. An attacker with database write access can exploit this to execute arbitrary code through gadget chains in loaded classes.

JSON encoding avoids this entirely: `json_decode()` returns only scalar values, arrays, and objects as `stdClass` instances without triggering object instantiation or magic methods. This removes the object injection vector.

The `allowed_classes` option (available in PHP 7.0+) is a stopgap for legacy scenarios: `['allowed_classes' => false]` prevents any object instantiation, though it converts serialized objects to `__PHP_Incomplete_Class` instances. This is safer than unrestricted deserialization but still not ideal for long-term maintenance.

For new data and ongoing development, JSON is the recommended format—it is safer, language-portable, and widely supported across PHP versions.
