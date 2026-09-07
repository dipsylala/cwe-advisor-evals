## Verdict

**CONFIRMED** - The vulnerability is real and exploitable. The prefix-based allowlist can be bypassed by an attacker creating a malicious class with a name starting with "com.example.report".

## Source

The source is the untrusted `ObjectInputStream` parameter `in` passed to the `readReport()` method. The attacker controls the serialized data stream.

## Fix

### File: ReportPayloadReader.java

```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Set;

public class ReportPayloadReader {
    // Explicit allowlist with specific class names instead of prefix matching
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.report.Report",
        "com.example.report.ReportData",
        "java.lang.String",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.util.LinkedList",
        "[Ljava.lang.Object;"
    );

    public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                // Let stream-size and depth limits pass through
                return ObjectInputFilter.Status.UNDECIDED;
            }
            // Use exact class name matching with explicit allowlist instead of prefix matching
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

The original code used a prefix-based allowlist (`clazz.getName().startsWith("com.example.report")`) which is bypassable: an attacker can craft a malicious class with a name like `com.example.report.Evil` or `com.example.report$Exploit` that passes the prefix check but executes arbitrary code during deserialization.

The fix replaces prefix matching with an explicit allowlist of specific, known-safe class names. Only classes whose fully-qualified names are in the `ALLOWED_CLASSES` set are permitted to deserialize. The allowlist includes:

1. **Application classes**: `com.example.report.Report` and `com.example.report.ReportData` - the actual domain objects expected to be deserialized
2. **Utility types**: `java.lang.String`, `java.util.ArrayList`, `java.util.HashMap`, `java.util.LinkedList` - container types commonly used in serialized objects
3. **Array types**: `[Ljava.lang.Object;` - object arrays that legitimate payloads may contain

Returning `UNDECIDED` when `clazz == null` allows stream-level limits (array depth, size, reference counts) to be applied without rejection, preserving the filter framework's other defensive capabilities.

## Behaviour changes

- **Before**: Prefix-based checks allowed any class starting with "com.example.report" to deserialize, including attacker-controlled malicious classes in that namespace.
- **After**: Only explicitly listed class names can deserialize. Any class not in the allowlist is rejected before instantiation, eliminating gadget chain exploitation.
- **Legitimate use**: Serialized data using only the allowed classes continues to work. Data using unapproved classes (including any malicious payloads) is rejected.
