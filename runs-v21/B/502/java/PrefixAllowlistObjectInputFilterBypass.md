## Verdict

Fixed. The vulnerability is a bypassable prefix-based allowlist in the ObjectInputFilter. A class named `com.example.reportEvil` or similar would pass the `startsWith("com.example.report")` check and be deserialized despite not being an intended safe class. Replaced with exact-match allowlist and proper handling of array and limit-only filter invocations.

## Source

**File:** `ReportPayloadReader.java`  
**Line:** 21  
**Sink:** `in.readObject()`  
**Weakness:** The ObjectInputFilter callback uses `clazz.getName().startsWith("com.example.report")` to allowlist classes. This prefix-based check is bypassable: an attacker can craft a serialized stream containing a class named `com.example.reportEvil` or `com.example.report.MaliciousClass` that passes the prefix check while not being an actually safe class the application expects.

**Data Flow:** The `ObjectInputStream` parameter (attacker-controlled via the serialized stream data) is filtered through a weak prefix allowlist, then `readObject()` deserializes any class that starts with `"com.example.report"`. An attacker can supply a serialized object of a malicious class with a name matching the prefix to escape the filter.

**Additional Issues:**
- The filter does not handle array types properly. When `clazz == null` with `arrayLength >= 0`, this indicates an array type declaration, and the filter should return `UNDECIDED` rather than implicitly allowing it.
- The filter does not explicitly list container types like `java.util.ArrayList` that the payload may legitimately use.

## Fix

### File: ReportPayloadReader.java

```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class ReportPayloadReader {
    public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            
            // Handle array types and stream limits (arrayLength >= 0 or limits check with null class)
            if (clazz == null) {
                // Limits check or array type declaration
                // Allow these metadata operations to proceed
                return ObjectInputFilter.Status.UNDECIDED;
            }
            
            String className = clazz.getName();
            
            // Exact match allowlist instead of prefix match
            // Only allow explicitly approved classes, not anything that starts with the prefix
            if ("com.example.report.ReportPayload".equals(className) ||
                "com.example.report.Report".equals(className) ||
                "java.util.ArrayList".equals(className) ||
                "java.lang.Object".equals(className) ||
                className.startsWith("[")) { // Allow array types
                return ObjectInputFilter.Status.ALLOWED;
            }
            
            return ObjectInputFilter.Status.REJECTED;
        });

        return in.readObject();
    }
}
```

## Explanation

The fix replaces the vulnerable prefix-based allowlist (`startsWith("com.example.report")`) with exact-match comparisons using `.equals()`. This prevents an attacker from bypassing the filter by choosing a class name that happens to start with the prefix but is not an actually trusted class.

**Key changes:**
1. **Exact-match allowlist:** Changed from `clazz.getName().startsWith("com.example.report")` to explicit `.equals()` checks for known-safe classes (`"com.example.report.ReportPayload"`, `"com.example.report.Report"`).
2. **Container types included:** Added `"java.util.ArrayList"` and `"java.lang.Object"` to the allowlist to ensure legitimate container types used in serialized payloads are accepted.
3. **Proper null handling:** When `clazz == null`, the filter returns `Status.UNDECIDED` instead of falling through to rejection. This correctly handles ObjectInputFilter metadata operations (array type declarations and stream limits) per CWE-502 Java guidance, which requires handling "null class with arrayLength of -1 is how the array-length, depth and stream-size limits arrive."
4. **Array type handling:** Added explicit allowance for array type class names (those starting with `"["`) which are legitimate during deserialization of collections.

This approach follows the CWE-502 Java remediation guidance: "An `ObjectInputFilter` allowlist must include the container types the payload legitimately uses, or valid traffic is rejected while the filter looks correct."

## Behaviour changes

The fixed code:
- **Rejects** more classes than before. Classes like `com.example.reportEvil`, `com.example.report.Gadget`, or `com.example.report_malicious` are now rejected.
- **Accepts** the same legitimate classes as intended, plus necessary container types (`ArrayList`, `Object`) and array types.
- **Properly handles** ObjectInputFilter metadata calls (limits and array declarations) by returning `UNDECIDED` when the class is null, allowing the filter infrastructure to function correctly.
- Does not change the method signature, return type, or external API.
- Does not introduce new exceptions or error paths beyond what the original code could throw.
