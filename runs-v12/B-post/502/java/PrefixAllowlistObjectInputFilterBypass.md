## Verdict

Exploitable. The prefix-based allowlist using `startsWith()` can be bypassed by crafting class names that match the prefix but are malicious or unexpected. For example, `com.example.report.Evil` or `com.example.report_gadget` would pass the filter despite being outside the intended allowlist.

## Source

Untrusted serialized data from the `ObjectInputStream` parameter passed to the `readReport()` method. The data source is not validated before deserialization and relies entirely on the object input filter for protection.

## Fix

Replace the prefix-based allowlist with exact class name matching. Use an explicit set of allowed classes and check for exact membership rather than prefix matching:

**Vulnerable Code:**
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

    // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here.
    return in.readObject();
}
```

**Fixed Code:**
```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        
        String className = clazz.getName();
        // Only allow specific known-safe classes
        if (className.equals("com.example.report.Report") ||
            className.equals("com.example.report.ReportData") ||
            className.equals("java.util.ArrayList") ||
            className.equals("java.util.HashMap") ||
            className.equals("java.lang.String") ||
            className.equals("java.lang.Integer") ||
            className.equals("[Ljava.lang.Object;")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    });

    return in.readObject();
}
```

## Explanation

The vulnerability lies in the use of `startsWith()` for class allowlisting, which permits any class whose name begins with the prefix `"com.example.report"`. This allows attackers to bypass the filter by crafting payloads with class names like `com.example.report.UnintendedClass` or similar variants that match the prefix but are not legitimate report classes. The fix replaces the prefix check with exact class name matching using `equals()`, permitting only specific known-safe classes to be deserialized. This follows the CWE-502 Java guidance principle: "Enforce strict type whitelisting and class instantiation controls" by checking for exact class membership rather than a broad prefix pattern. The allowlist includes both the intended domain classes (`com.example.report.Report`, `com.example.report.ReportData`) and container/primitive types that may legitimately appear during object deserialization.

## Behaviour changes

None. The filter behavior remains the same from the caller's perspective: the `readObject()` call still returns a deserialized object. The only change is in the allowlist enforcement strategy—from permissive prefix matching to restrictive exact-match validation. Callers that rely on the filter rejecting unexpected classes will see stricter enforcement, which closes the bypass rather than introducing a regression.
