## Verdict

exploitable (confidence: high)

CWE-476 (NULL Pointer Dereference), Java. `reservedBySku` is a `Map<String, Integer>` supplied to the constructor with no guarantee every `sku` passed to `availableToPromise` has an entry. `Map.get` on a miss returns `null`, and the assignment to the primitive `int reserved` triggers unboxing, which throws `NullPointerException`. There is no visible dereference (no `.` on the failing line) - this is the invisible-unboxing case the Java guidance calls out specifically.

## Source

- **Source**: `reservedBySku.get(sku)` at line 14 - a lookup in a caller-supplied map, keyed by a caller-supplied `sku`, with no prior `containsKey`/`isPresent` check and no guarantee the map is exhaustive over every SKU that can be passed in.
- **Sink**: the implicit unboxing at the same line, where the `Integer` result of `get()` is assigned to the primitive local `int reserved`. Any SKU not present in `reservedBySku` (never reserved, or reservation cleared) makes `get()` return `null`, and the unboxing conversion throws `NullPointerException` before line 15 is even reached.
- Single-file case: no other call sites of `availableToPromise` or producers of `reservedBySku` are present in this chain to audit.

## Fix

Vulnerable code:

```java
public int availableToPromise(String sku, int onHand) {
    // SAST FINDING: CWE-476 (NULL Pointer Dereference) reported here. Sink is the next statement.
    int reserved = reservedBySku.get(sku);
    return onHand - reserved;
}
```

Fixed code:

```java
public int availableToPromise(String sku, int onHand) {
    int reserved = reservedBySku.getOrDefault(sku, 0);
    return onHand - reserved;
}
```

## Explanation

`Map.getOrDefault(sku, 0)` replaces the ambiguous `get()` + implicit-unbox pattern with an explicit contract: a SKU absent from `reservedBySku` means nothing is currently reserved against it, so the default of `0` is the semantically correct stand-in, not an arbitrary placeholder. The unboxing conversion now always has a non-null `Integer` (or the primitive default) to work with, so the invisible-dereference path is closed at the point the value is obtained, per the Java guidance's preferred fix point (`getOrDefault`/`orElseThrow` at the lookup, not a check bolted onto the crash site). `onHand - reserved` and the method's return type are unchanged, so callers see the same signature and the same result for every SKU that does have a reservation entry.

## Behaviour changes

- For a `sku` absent from `reservedBySku`, the method previously threw `NullPointerException`; it now returns `onHand` unchanged (treating "no entry" as "zero reserved"). This is the intended fix - absence is a legitimate, expected state for a SKU with no active reservation, not an error condition - but it does change the method from throwing to returning a value for that input, so any caller that was relying on (or incidentally catching) the exception for unknown SKUs needs to re-check that assumption.
- No other differences: arguments, return type, and behaviour for SKUs present in the map are unchanged.
