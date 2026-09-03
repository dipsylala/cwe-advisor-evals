## Verdict
exploitable

## Source
The `ObjectInputStream in` parameter at line 8, which reads untrusted serialized data from an external source.

## Fix

**Vulnerable code (line 8-21):**
```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (clazz.getName().startsWith("com.example.report")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    });

    // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
    return in.readObject();
}
```

**Fixed code:**
```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            // Handle stream-level constraints: array length, depth, stream size limits
            if (filterInfo.arrayLength() >= 0) {
                return filterInfo.arrayLength() <= 10000 ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
            }
            if (filterInfo.depth() >= 0) {
                return filterInfo.depth() <= 100 ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
            }
            if (filterInfo.streamSize() >= 0) {
                return filterInfo.streamSize() <= 1000000 ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.UNDECIDED;
        }
        
        // Explicit class allowlist - only named classes allowed, no prefix matching
        String className = clazz.getName();
        if (className.equals("com.example.report.Report") ||
            className.equals("com.example.report.ReportData") ||
            className.equals("java.util.ArrayList") ||
            className.equals("[Ljava.lang.Object;") ||
            className.equals("java.util.HashMap") ||
            className.equals("java.util.LinkedList")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        
        return ObjectInputFilter.Status.REJECTED;
    });

    return in.readObject();
}
```

## Explanation
The original code uses a prefix-based allowlist (`startsWith("com.example.report")`) which is exploitable because it permits any class in that namespace, including potentially malicious subclasses or gadget chains. Additionally, it only handles the `serialClass()` field and returns `UNDECIDED` for null, missing critical stream-level constraint checks for array length, depth, and stream size that are essential to prevent denial-of-service attacks. The fix implements three key improvements: (1) explicit per-class allowlisting using exact name matching instead of prefix matching to prevent namespace bypass; (2) proper handling of stream-level constraints (arrayLength, depth, streamSize) as specified in the filter contract; and (3) inclusion of necessary container types (ArrayList, HashMap, LinkedList) that legitimate deserialization requires. This ensures that only known-safe classes can be deserialized while also preventing malformed stream attacks.

## Behaviour changes
The `setObjectInputFilter` callback now rejects classes outside the explicit allowlist, which is stricter than the original prefix check and may reject previously-accepted classes not in the whitelist. All stream-level constraint checks are newly added; they were previously unhandled (returning UNDECIDED). Container types are now explicitly allowed, which were previously rejected by the prefix filter. These changes together prevent gadget-chain exploitation while maintaining legitimate deserialization of expected types.
