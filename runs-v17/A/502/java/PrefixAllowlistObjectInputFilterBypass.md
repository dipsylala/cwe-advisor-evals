## Verdict
The prefix-based allowlist using `startsWith()` is vulnerable to bypass. An attacker can create malicious classes with names beginning with the allowed prefix to bypass the filter. The fix replaces it with an explicit allowlist using exact class name matching.

## Source
File: `ReportPayloadReader.java`, line 21 (`in.readObject()`)

Vulnerability: The `ObjectInputFilter` at line 9 uses `clazz.getName().startsWith("com.example.report")` as an allowlist check. This can be bypassed by creating a gadget chain class with a name that starts with the allowed prefix.

## Fix

### File: ReportPayloadReader.java
```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Set;

public class ReportPayloadReader {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "cases.deserialization.SafeReport",
        "cases.deserialization.ReportMetadata",
        "java.lang.String",
        "java.util.ArrayList",
        "java.util.HashMap"
    );

    public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            if (ALLOWED_CLASSES.contains(clazz.getName())) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        });

        return in.readObject();
    }
}
```

## Explanation
The original code used a prefix-based allowlist (`startsWith("com.example.report")`), which allows any class whose name begins with that prefix. An attacker can create a malicious class with a name like `com.example.reportMalicious` or `com.example.report.Gadget` that would pass this check.

The fix replaces this with an explicit allowlist stored in a `Set` that contains only the class names that are actually safe to deserialize. The filter now uses exact matching (`Set.contains()`) instead of prefix matching. This ensures only explicitly approved classes are deserialized.

The allowlist should be tailored to include only the classes your application actually needs (e.g., `SafeReport`, `ReportMetadata`, and any standard library classes required for deserialization). Classes not in the set are rejected, preventing gadget chain exploitation.
