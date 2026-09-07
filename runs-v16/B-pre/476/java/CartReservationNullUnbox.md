## Verdict

Exploitable. Any call to `availableToPromise()` with a SKU not present in the `reservedBySku` map will throw `NullPointerException` when the `Map.get()` result (null) is unboxed to the `int` primitive.

## Source

The source is the `Map.get(sku)` call within the `availableToPromise()` method. The `Map<String, Integer>` field `reservedBySku` can return `null` when a key is not present. The null value flows directly to the unboxing site at line 14, where it is assigned to `int reserved`.

## Fix

**Vulnerable code:**
```java
public int availableToPromise(String sku, int onHand) {
    int reserved = reservedBySku.get(sku);  // NPE if sku not in map
    return onHand - reserved;
}
```

**Fixed code:**
```java
public int availableToPromise(String sku, int onHand) {
    int reserved = reservedBySku.getOrDefault(sku, 0);
    return onHand - reserved;
}
```

## Explanation

The fix replaces `Map.get()` with `Map.getOrDefault(sku, 0)`, which returns the mapped value if present or the default value (0) if the key is absent. This eliminates the null entirely before it reaches the unboxing site, preventing the NullPointerException. The default of 0 is semantically correct: if a SKU has no reservation record, the reserved quantity is zero. This follows the Java-specific guidance to handle absence explicitly at the producer (the map access) rather than adding a null check at the crash site.

## Behaviour changes

None. The `getOrDefault()` method preserves the original contract: it returns an `int` with the same semantics as the unsafe unboxing, but it handles the absent-key case safely by substituting the default. The return value and type of `availableToPromise()` remain unchanged.
