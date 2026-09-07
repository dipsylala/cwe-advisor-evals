## Verdict

**VULNERABLE.** The `ObjectInputFilter` at line 9-18 uses a prefix-based allowlist pattern (`clazz.getName().startsWith("com.example.report")`), which is bypassable. An attacker can craft a class with any name beginning with `"com.example.report"` and bypass the filter when deserializing at line 21. The prefix matching is too loose to constitute a reliable allowlist and does not prevent instantiation of gadget-chain classes.

## Source

The untrusted data source is the `ObjectInputStream in` parameter, which carries serialized objects from an attacker-controlled origin. At line 21, `in.readObject()` deserializes this untrusted data. The intermediate filter at lines 9-18 attempts to restrict which classes may be deserialized, but the prefix-based check is insufficient.

## Fix

Replace the prefix-based filter with an explicit per-class allowlist that names only known-safe classes:

```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        
        String className = clazz.getName();
        // Explicit allowlist of known-safe classes only
        if (className.equals("com.example.report.Report") ||
            className.equals("com.example.report.ReportData") ||
            className.equals("java.util.ArrayList") ||
            className.equals("java.util.HashMap") ||
            className.equals("[Ljava.lang.String;") ||
            className.equals("[Ljava.lang.Object;") ||
            className.equals("java.lang.String") ||
            className.equals("java.lang.Integer") ||
            className.equals("java.lang.Long") ||
            className.equals("java.lang.Double")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    });

    return in.readObject();
}
```

## Explanation

The vulnerability exists because prefix matching (`startsWith`) is not a reliable allowlist. An attacker can create a class named `com.example.report.gadget.EvilClass` that passes the prefix check but is actually a gadget-chain class that executes code during deserialization. The fix replaces the prefix-based check with explicit per-class equality checks. Each allowed class is named by its full qualified class name, eliminating ambiguity. Container types (`ArrayList`, `HashMap`, `String[]`, `Object[]`) that may legitimately appear in serialized payloads are included. Any class not on the explicit allowlist is immediately rejected. This approach follows the CWE-502 Java guidance: enforce strict type whitelisting by explicitly naming only known-safe classes, not patterns.

## Behaviour changes

The filter now only allows instances of precisely-named classes: the three example report classes and essential container/primitive types. Any class not in this set — including classes with names starting with `com.example.report` — will be rejected during deserialization, causing `ObjectInputStream.readObject()` to raise `java.io.InvalidClassException`. Applications using this reader must update any serialized payloads to use only classes in the allowlist, or extend the allowlist to include additional legitimate classes. If the set of allowed classes is not known in advance, this approach is not suitable; a better fix would be to replace Java serialization entirely with a data-only format like JSON (Jackson, Gson) where all producers can migrate together.
