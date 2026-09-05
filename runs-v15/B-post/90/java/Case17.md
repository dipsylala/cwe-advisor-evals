## Verdict
exploitable

## Source
The `data` parameter in `Case17B.handleSink()` receives untrusted user input (passed from `Case17A.handle()` to the public method). In this test case, the data is the hardcoded string `"foo"`, but the parameter is untrusted by contract and accepts any user-supplied value.

## Fix
**Vulnerable code (line 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
String[] filterArgs = {data};

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, new SearchControls());
```

## Explanation
The original code constructs an LDAP filter by concatenating untrusted user input directly into the filter expression. An attacker could supply input containing LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to break out of the intended filter structure and inject additional conditions. The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload, which accepts filter arguments separately via the `filterArgs` parameter. JNDI escapes each string-valued argument according to RFC 4515 (LDAP filter escaping) before interpreting it as a value rather than structure, preventing injection. The `new SearchControls()` argument is required by the parameterized overload signature to specify search scope and controls (using default values here).

## Behaviour changes
The third argument changed from `null` to a `String[]` array containing the user input, and a fourth argument `new SearchControls()` was added. These are required by the parameterized overload signature. The `SearchControls` default constructor uses the default search scope (`SUBTREE_SCOPE`), timeout (0 ms), and other defaults—matching the behavior of passing `null` to the original three-argument `search()` method, so the functional behavior is preserved.
