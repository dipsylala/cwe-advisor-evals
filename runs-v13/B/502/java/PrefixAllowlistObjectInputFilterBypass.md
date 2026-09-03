## Verdict

Confirmed CWE-502. The prefix-based allowlist using `clazz.getName().startsWith("com.example.report")` is exploitable: an attacker can craft a class name starting with the prefix (e.g., `com.example.report.MaliciousClass`) or use gadget chains from packages that coincidentally match the prefix. Exact class name matching or a strict allowlist is required instead.

## Source

File: `evals/cases/502/java/PrefixAllowlistObjectInputFilterBypass/ReportPayloadReader.java`, line 21

The `ObjectInputStream.readObject()` call is preceded by an `ObjectInputFilter` that attempts to allowlist classes by checking if the class name starts with `"com.example.report"`. This is overly permissive and does not reliably restrict deserialization to safe classes.

## Fix

Replace the prefix-based check with exact class name matching:

```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        
        String className = clazz.getName();
        // Exact allowlist of safe classes only
        if (className.equals("com.example.report.ReportEvent") ||
            className.equals("com.example.report.ReportMetadata") ||
            className.equals("java.util.ArrayList") ||
            className.equals("java.util.HashMap") ||
            className.equals("[Ljava.lang.Object;")) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        
        return ObjectInputFilter.Status.REJECTED;
    });

    return in.readObject();
}
```

**Alternative (recommended for cleaner code):** Use the string-based `ObjectInputFilter.Config.createFilter()` API with explicit class patterns and limits:

```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    String filterPattern = "com.example.report.ReportEvent;" +
                          "com.example.report.ReportMetadata;" +
                          "java.util.*;[Ljava.lang.Object;;" +
                          "maxdepth=10;maxrefs=1000;maxbytes=1000000;" +
                          "!*";
    
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(filterPattern);
    in.setObjectInputFilter(filter);

    return in.readObject();
}
```

## Explanation

The prefix-based allowlist is vulnerable because class names that begin with `"com.example.report"` are not inherently safe—an attacker can:
1. Create malicious classes under that package namespace
2. Use gadget chains from unexpected classes in the allowed package
3. Exploit case-sensitivity or package-naming tricks

The fix uses exact class name matching or explicit patterns, which provides strict control over which classes can be deserialized. The string-based filter approach (alternative) is recommended because:
- It clearly lists only the intended safe classes
- It includes necessary container types (`java.util.*`, `Object[]`) that legitimate payloads may use
- It enforces stream size and depth limits to prevent denial-of-service attacks
- The `!*` pattern at the end rejects anything not explicitly allowed, closing unexpected gadget chains

Both approaches comply with the JDK guidance: the filter is attached per-stream with `setObjectInputFilter()` (not `Config.setSerialFilter()`), and it returns `UNDECIDED` for null classes to let platform filtering run.

## Behaviour changes

- **Tighter filtering:** Only explicitly named classes are deserialized; any class not in the allowlist is rejected immediately
- **Stream limits:** The alternative approach adds depth, object count, and byte-size limits, preventing malformed or oversized payloads that could cause denial-of-service
- **No functional regression:** Legitimate payloads using the allowed report classes and standard containers will continue to deserialize correctly
- **Failure mode:** Payloads containing unexpected classes now fail fast with `Status.REJECTED` instead of being silently accepted by the prefix check
