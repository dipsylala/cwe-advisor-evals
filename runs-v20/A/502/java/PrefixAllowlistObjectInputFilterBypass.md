## Verdict

Confirmed. The `ObjectInputFilter` installed on the stream is a raw string-prefix check
(`clazz.getName().startsWith("com.example.report")`) rather than a package-boundary check. Any
class whose fully-qualified name merely begins with the literal characters `com.example.report` -
for example a gadget class in an attacker-controlled or otherwise loaded package named
`com.example.reportinjector.Gadget` or `com.example.reportXXX.Evil` - satisfies `startsWith` and
is returned `ALLOWED`, even though it is not a member of the intended `com.example.report`
package tree. `in.readObject()` on line 21 then deserializes whatever the filter let through, so
the allowlist can be bypassed by any class on the classpath (or supplied via a malicious jar) that
happens to share the prefix, restoring full deserialization-of-untrusted-data exposure despite the
filter appearing to be in place.

## Source

`ObjectInputStream in` passed into `readReport(ObjectInputStream in)` - the caller supplies a
stream backed by attacker-controlled bytes (a network payload, uploaded report file, or queue
message), and `in.readObject()` is invoked directly on it.

## Fix

### File: ReportPayloadReader.java

```java
package cases.deserialization;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

public class ReportPayloadReader {
    private static final String ALLOWED_PACKAGE = "com.example.report";

    public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.setObjectInputFilter(filterInfo -> {
            Class<?> clazz = filterInfo.serialClass();
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            // Array element types must be unwrapped, otherwise "[Lcom.example.report.Foo;"
            // never matches the plain package-name comparisons below.
            while (clazz.isArray()) {
                clazz = clazz.getComponentType();
            }
            if (clazz.isPrimitive()) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            String name = clazz.getName();
            // Require an exact package match or a "." boundary immediately after the prefix,
            // not a bare startsWith, so a sibling package such as
            // "com.example.reportinjector" cannot satisfy the allowlist by sharing characters
            // with "com.example.report".
            boolean inAllowedPackage = name.equals(ALLOWED_PACKAGE)
                    || name.startsWith(ALLOWED_PACKAGE + ".");
            if (inAllowedPackage) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        });

        return in.readObject();
    }
}
```

## Explanation

The mechanism, not just the symptom, was the bug: `String.startsWith(prefix)` matches on raw
characters, not on package segments, so it treats `com.example.report` and
`com.example.reportinjector` as the same allowed namespace. The fix keeps the same allowlist
policy and the same filter installation point - it does not swap in a denylist or a different
deserialization mechanism, since the filter itself is the correct primary defence for
`ObjectInputStream` and only its boundary logic was wrong. It changes the comparison to require
either an exact match on the package name or that the prefix be followed by a `.` before the rest
of the class name, which is the standard way to test "is this class in package X (or a
subpackage)" without accepting a longer sibling package name that merely shares a character
prefix. Array component types are unwrapped first because `Class.getName()` for an array (e.g.
`[Lcom.example.report.Foo;`) would otherwise never satisfy either comparison, which would either
silently break legitimate array fields or tempt a weaker fix such as re-introducing a bare
`contains`/`startsWith` check; primitives are allowed outright since they carry no class-loading
or gadget risk. No other behavior changes: unresolvable/proxy classes still fall through to
`UNDECIDED` for the stream's default handling, and everything outside the `com.example.report`
tree is still `REJECTED`, so legitimate payloads that were passing before continue to pass and the
prefix-bypass class of payloads is now rejected.
