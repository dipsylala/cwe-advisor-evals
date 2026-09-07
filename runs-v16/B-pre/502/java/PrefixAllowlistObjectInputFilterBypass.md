## Verdict
exploitable

## Source
ObjectInputStream parameter in readReport method - untrusted input from caller

## Fix

**Vulnerable code:**
```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.setObjectInputFilter(filterInfo -> {
        Class<?> clazz = filterInfo.serialClass();
        if (clazz == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (clazz.getName().startsWith("com.example.report")) {  // Prefix-based allowlist - bypassed by com.example.report.Evil
            return ObjectInputFilter.Status.ALLOWED;
        }
        return ObjectInputFilter.Status.REJECTED;
    });

    return in.readObject();
}
```

**Fixed code:**
```java
public Object readReport(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Use explicit class allowlist with string-based filter form
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
        "com.example.report.ReportPayload;" +
        "java.util.ArrayList;[Ljava.lang.Object;;" +
        "java.base/*;" +
        "!*"
    );
    in.setObjectInputFilter(filter);
    return in.readObject();
}
```

## Explanation
The prefix-based allowlist check using `startsWith("com.example.report")` is insufficient because an attacker can craft a malicious class that starts with this prefix - for example, `com.example.report.Evil` - while containing gadget chains for code execution. The fix replaces the prefix pattern with an explicit allowlist of specific class names, listing only the classes known to be safe for deserialization (`com.example.report.ReportPayload`), the container types the payload legitimately uses (`java.util.ArrayList`, `[Ljava.lang.Object;`), necessary framework classes (`java.base/*`), and a final rejection rule (`!*`) to deny everything else. The string-based `ObjectInputFilter.Config.createFilter()` API provides a declarative, audit-friendly format for this allowlist that is harder to bypass than pattern matching.

## Behaviour changes
The fixed code uses `ObjectInputFilter.Config.createFilter(String)` instead of a hand-written lambda callback. This changes:
- The allowlist is now explicit: only `com.example.report.ReportPayload`, `java.util.ArrayList`, arrays of Object, and `java.base` package classes are accepted; all other classes are rejected
- The filter is installed with `setObjectInputFilter(filter)` before the `readObject()` call, same as the original
- No changes to the method's return type, parameters, or exception handling
- The sink contract is preserved: `readObject()` still returns the deserialized object or throws on error
