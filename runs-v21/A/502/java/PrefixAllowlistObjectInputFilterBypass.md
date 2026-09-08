## Verdict
Real issue. The prefix-based allowlist is vulnerable to bypass: an attacker can craft a class name that matches the prefix pattern but contains gadget chain code.

## Source
The vulnerable code at line 14 uses `clazz.getName().startsWith("com.example.report")` to filter deserialized classes. This prefix matching is insufficient because an attacker can create a malicious class with a name like `com.example.report.Gadget` that satisfies the prefix but executes arbitrary code during deserialization.

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
        "com.example.report.ReportData",
        "com.example.report.ReportMetadata"
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
Prefix-based allowlists for `ObjectInputFilter` are vulnerable because an attacker can craft a class name matching the prefix pattern while containing malicious deserialization gadgets. The fix replaces the prefix check with an explicit allowlist of exact class names that are known to be safe to deserialize. This approach:

1. **Eliminates the bypass vector**: Only explicitly named classes are allowed; no class matching a prefix pattern can slip through.
2. **Makes the safe classes explicit**: The `ALLOWED_CLASSES` set clearly documents which classes the application expects to deserialize, making security audits straightforward.
3. **Follows the principle of least privilege**: Only the necessary classes are whitelisted; everything else is rejected by default.

To use this in production, replace the class names in `ALLOWED_CLASSES` with the actual classes your application deserializes.
