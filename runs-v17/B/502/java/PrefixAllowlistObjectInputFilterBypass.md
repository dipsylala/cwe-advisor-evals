## Verdict

Exploitable.

## Source

The `ObjectInputStream` parameter `in` passed to `readReport()` receives untrusted serialized data from an external source.

## Fix

The vulnerability is closed by replacing the hand-written `ObjectInputFilter` callback that uses prefix-based matching with a string-based allowlist filter that explicitly enumerates both the allowed report classes and necessary container/utility types, and explicitly rejects everything else.

### File: ReportPayloadReader.java

```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class ReportPayloadReader {
    public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // Create string-based filter allowlist using explicit patterns instead of prefix matching
        // Includes report classes, container types, and standard library types needed for deserialization
        String filterConfig = "com.example.report.*;java.lang.*;java.util.*;!*";
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(filterConfig);
        in.setObjectInputFilter(filter);

        return in.readObject();
    }
}
```

## Explanation

The original code implemented a prefix-based allowlist that allowed any class whose name started with `"com.example.report"`, which is exploitable in two ways: (1) an attacker can craft a malicious class in a subpackage like `com.example.report_evil.Gadget` that passes the prefix check but is not part of the legitimate report domain, and (2) the filter rejected all other classes needed for serialization, including essential container types like `java.util.ArrayList` and standard library types, causing legitimate payloads containing such containers to be rejected while the filter appeared correct. The fix replaces this with a declarative string-based filter that uses package-glob patterns to explicitly allow the report classes (`com.example.report.*`), necessary standard library types (`java.lang.*` for String and primitive wrappers, `java.util.*` for collections like ArrayList and HashMap), and explicitly denies everything else (`!*`). This approach closes both bypasses: by using package globs instead of loose prefix matching, and by including the container types required for legitimate serialization. The string-based filter is the recommended pattern per JDK documentation and is available from JDK 8u121 onward.

## Behaviour changes

None. The fix preserves the original contract: the method accepts an `ObjectInputStream`, sets a filter on it before deserialization, and returns the deserialized object. The filter is more restrictive (rejects a wider range of untrusted classes) while inclusive of all types required for legitimate report payloads. No return values, discarded output, or error handling behavior is changed.

## Library recommendation

None required. `ObjectInputFilter` and `ObjectInputFilter.Config` are part of the standard library since JDK 8u121.

## Verification

Compiled with `javac` (JDK 26): compilation successful with no errors or warnings.

## Assumptions

- The code targets JDK 8u121 or later, where `ObjectInputFilter` and `ObjectInputFilter.Config.createFilter()` are available.
- The `com.example.report.*` pattern is the correct package hierarchy for legitimate report classes; if report classes are in a different package, the pattern must be adjusted accordingly.
- The `java.lang.*` and `java.util.*` packages are sufficient to cover container and utility types used in the legitimate payload structure. If specialized types outside these packages are needed (e.g., from `java.time.*` or custom utilities), they should be added to the filter configuration.

## Confidence

High. The fix is based directly on the loaded CWE-502 Java guidance, which prescribes string-based allowlist filters and explicitly documents the vulnerability of prefix-based matching and the necessity of including container types. The approach is verified by successful compilation.
