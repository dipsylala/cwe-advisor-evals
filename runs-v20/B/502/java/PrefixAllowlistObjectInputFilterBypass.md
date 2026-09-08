## Verdict

Confirmed. The `ObjectInputFilter` installed on the stream is bypassable and does not provide the class allowlist the code intends, so `in.readObject()` remains reachable with insufficiently constrained class construction.

## Source

`ObjectInputStream in`, the parameter to `readReport(ObjectInputStream in)`. The stream's bytes originate outside this method (the caller feeds it attacker-influenced report-payload data); nothing in this file validates or signs the bytes before they reach the sink.

## Fix

Language: Java. Guidance loaded: `cwe/502/INDEX.md` and `cwe/502/java/INDEX.md`.

Data flow: `in` (source, attacker-controlled bytes) -> `in.setObjectInputFilter(...)` installs a per-stream `ObjectInputFilter` callback intended to restrict which classes may be instantiated -> `in.readObject()` (sink, line 21) performs the actual deserialization and object construction.

Sink contract (`ObjectInputStream.readObject()`):
- Returns: the deserialized `Object`, passed straight back to the caller unchanged.
- Discards: nothing beyond what the filter itself rejects.
- Arguments left implicit: none - `readObject()` takes no arguments; the security-relevant configuration is the filter registered on the stream before the call.
- Failure behaviour: throws `InvalidClassException` when the installed filter returns `Status.REJECTED` for a class encountered in the stream, and `ClassNotFoundException`/`IOException` as already declared by the method. The fix must preserve this - a payload outside the allowlist should still fail with `InvalidClassException`, not silently succeed.

The vulnerability is in the filter's allow condition, not in the presence of a filter or in the sink call itself. `clazz.getName().startsWith("com.example.report")` does unanchored string-prefix matching against the fully qualified class name. Because the literal has no trailing separator, it matches any class whose name merely begins with that substring, not only classes that are actually inside the `com.example.report` package - for example a class named `com.example.reportXYZ.Gadget` (a sibling package) or `com.example.reportEvil` (a class named `reportEvil` directly in package `com.example`) both satisfy `startsWith("com.example.report")` while being outside the intended package. If any such class exists on the classpath (application or dependency code), the filter allows it through as `Status.ALLOWED`, defeating the allowlist and reopening the same code-execution/DoS surface CWE-502 targets, exactly as `cwe/502/java/INDEX.md` describes for a hand-written `ObjectInputFilter` callback that "looks correct" but admits unintended classes.

The minimal fix anchors the prefix at a package boundary by appending the separator dot to the literal, so the check can only match classes actually inside `com.example.report` (and its subpackages), never a same-prefix sibling.

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
            if (clazz == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            if (clazz.getName().startsWith("com.example.report.")) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            return ObjectInputFilter.Status.REJECTED;
        });

        // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
        return in.readObject();
    }
}
```

## Explanation

The only change is the allowlist literal: `"com.example.report"` becomes `"com.example.report."`. `String.startsWith` is a literal, unanchored comparison, so without the trailing dot the check matches on shared characters alone and cannot distinguish the intended package from any other identifier that happens to start with the same letters. Adding the separator forces the match to land exactly on a package boundary - a class only satisfies the check if its fully qualified name is `com.example.report.<Something>`, which is what "class is in the `com.example.report` package" actually means in a dotted name. Every class the filter was meant to allow (anything genuinely under `com.example.report`) still matches; every same-prefix impostor (`com.example.reportXYZ.*`, `com.example.reportEvil`) now falls through to `Status.REJECTED`. No new API, import, or control-flow path was introduced - `clazz`, `filterInfo`, and the three `ObjectInputFilter.Status` values are all already used identically in the original code, and this is verified by compiling the fixed file standalone with `javac` (clean compile, no diagnostics).

## Behaviour changes

- Classes whose fully qualified name starts with the literal `com.example.report` but are not actually inside that package (e.g. `com.example.reportXYZ.Gadget`, `com.example.reportEvil`) are now rejected by the filter and cause `readObject()` to throw `InvalidClassException` for any payload that references them. This is the intended effect of closing the bypass; treat it as a behaviour change only if such a class was ever legitimately expected to deserialize here, which the class's own name makes unlikely.
- Classes genuinely inside `com.example.report` (and its subpackages, e.g. `com.example.report.sub.Foo`) continue to be allowed exactly as before - no change for legitimate report payloads.
- The `UNDECIDED` handling for the depth/array-length/stream-size probe calls (`clazz == null`), the `REJECTED` fallthrough, the method signature, and the returned/thrown types are all unchanged.
