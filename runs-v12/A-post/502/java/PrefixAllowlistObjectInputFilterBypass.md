## Verdict

The filter allows deserialization of any class whose name starts with "com.example.report", which permits classes not explicitly vetted for deserialization safety. An attacker can supply a malicious class with a name like `com.example.report.Evil` or exploit package-naming collisions to bypass the intended allowlist.

## Source

The vulnerability is in the ObjectInputFilter lambda at lines 9-18. The filter checks `clazz.getName().startsWith("com.example.report")` (line 14), which is a prefix-based allowlist that accepts any class matching the pattern, not just intended safe classes.

## Fix

Replace the prefix-based allowlist with an exact allowlist of explicitly vetted classes:

```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.Set;

public class ReportPayloadReader {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.report.SafeReport",
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

Prefix-based allowlists for deserialization are inherently loose. An attacker can introduce a class whose fully qualified name starts with the allowed prefix but that performs malicious actions on instantiation or field assignment. The safe approach is exact-match allowlisting: define a static set containing only the fully qualified names of classes you intend to deserialize, and reject anything else. This prevents namespace collisions and ensures only explicitly vetted types are accepted. For each allowed class, verify at design time that its deserialization is safe—that no field assignment, `readObject()` override, or constructor runs untrusted code.

