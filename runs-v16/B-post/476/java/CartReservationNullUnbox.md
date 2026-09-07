## Verdict

Exploitable. The finding is a real null pointer dereference caused by unboxing a null value returned from `Map.get()`.

## Source

The source is `reservedBySku.get(sku)` at line 14, where `reservedBySku` is a `Map<String, Integer>` passed in the constructor. The map can legitimately not contain a key for the given SKU, in which case `get()` returns `null`.

## Fix

**Vulnerable code (line 14):**
```java
int reserved = reservedBySku.get(sku);
```

**Fixed code:**
```java
int reserved = reservedBySku.getOrDefault(sku, 0);
```

## Explanation

The vulnerability occurs because `Map.get(sku)` returns `Integer` (boxed), which can be `null` when the key is not present. The assignment to `int` (primitive) triggers automatic unboxing, which throws `NullPointerException` when the value is `null`. The fix replaces `get()` with `getOrDefault()`, which returns a default value of `0` when the key is absent, eliminating the null dereference. This is the idiomatic Java pattern recommended by the language for handling optional map lookups and makes the absence case explicit in the code rather than hidden in a null check.

## Behaviour changes

None. The fix preserves the existing contract: when a SKU is not in the map, the reservation count defaults to 0, which is the semantically correct behavior (no items reserved means available items equal items on hand). The change only makes this behavior explicit and prevents the crash.
