## Verdict

Exploitable. The `data` parameter is concatenated directly into an LDAP filter string without any escaping or sanitization, allowing attackers to inject LDAP query metacharacters and modify the query structure to access unintended directory data.

## Source

The `data` parameter in `Case17B.handleSink()` (line 17), passed from `Case17A.handle()` (line 18). In the test case it is hardcoded as `"foo"`, but the parameter receives untrusted input in real usage.

## Sink

Line 32 in Case17B.java: `directoryContext.search("", search, null)` - the filter string `search` is constructed via concatenation on line 29.

## Fix

**Vulnerable code (lines 29, 32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code (lines 29–32):**
```java
String search = "(cn={0})";
SearchControls cons = new SearchControls();

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[]{data}, cons);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload, which takes the filter template as the second argument and user data separately via the `filterArgs` parameter (Object array). JNDI automatically escapes each string-valued argument according to RFC 4515 before substituting it into the filter, neutralizing LDAP metacharacters like `*`, `(`, `)`, `\`, and NUL. The parameterized overload requires a trailing `SearchControls` argument; here we pass a default instance to preserve the original search scope and behavior.

## Behaviour changes

None. The fix preserves the original sink contract:
- **Returns**: `NamingEnumeration<SearchResult>` as before, iterated over identically in the subsequent while loop (lines 33–47)
- **Discards**: Nothing changes
- **Arguments left implicit**: `SearchControls` defaults to a subtree scope search, which matches the original `null` behavior
- **Failure behaviour**: `search()` still throws `NamingException` on directory errors, caught on line 49
