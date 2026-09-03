## Verdict

Exploitable

## Source

Line 7-9: Database query result `$row['cart_data']`, fetched from the `carts` table without integrity verification. The data was previously stored via an application interface and can be poisoned by an attacker with database write access or through unvalidated application input.

## Fix

**Vulnerable code:**
```php
// Line 16: SAST FINDING: CWE-502 (Deserialization of Untrusted Data)
return unserialize($row['cart_data']);
```

**Fixed code:**
```php
return json_decode($row['cart_data'], true);
```

## Explanation

The `unserialize()` function reconstructs PHP objects and invokes magic methods (`__wakeup()`, `__destruct()`, `__toString()`) during deserialization. Attackers who can inject serialized object data into the `cart_data` column can trigger gadget chains to achieve arbitrary code execution or property manipulation. Replacing `unserialize()` with `json_decode()` treats the data as inert values (arrays/strings) rather than executable objects, eliminating magic method invocation and class instantiation during deserialization. The fix requires that cart data be stored as JSON rather than PHP serialized format; this is a primary design change rather than a hotfix, typically implemented during a data migration phase where legacy serialized cart data is converted to JSON and stored with `json_encode()` instead of `serialize()`.

## Behaviour changes

- Data format shifts from PHP serialized (`serialize()` output) to JSON. Application code that writes cart data must use `json_encode()` instead of `serialize()`.
- `json_decode($row['cart_data'], true)` returns an associative array; `unserialize()` could return typed objects. If cart data contains objects with specific properties, the application must be adapted to work with plain arrays or objects via `json_decode()` without the `true` flag.
- Invalid JSON returns `null` (PHP 7.3+); invalid serialized data throws `Error` (PHP 7.1+) or returns `false` (PHP < 7.0). Error handling logic must account for `null` as a valid unserialize failure state, distinct from an empty array `[]`.
