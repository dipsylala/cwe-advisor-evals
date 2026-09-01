## Verdict

**Exploitable.** The `data` parameter is concatenated directly into an LDAP filter without escaping or parameterization, allowing LDAP injection.

## Source

The `data` parameter to `Case17B.handleSink()` (line 17 of Case17B.java) is user-controlled and passed from Case17A.

## Fix

Replace the concatenated filter string with a parameterized query using JNDI's `{0}` placeholder syntax:

**Vulnerable code (lines 29–32):**
```java
String search = "(cn=" + data + ")";
// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String filterPattern = "(cn={0})";
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterPattern, new String[]{data}, null);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized `search()` overload, which accepts filter arguments separately from the filter expression template. JNDI automatically escapes each string argument according to RFC 4515 (LDAP filter escaping), preventing special characters like `*`, `(`, `)`, and `\` from being interpreted as query syntax. The replacement preserves the existing sink contract: it returns the same `NamingEnumeration<SearchResult>` type and maintains identical iteration semantics downstream. No library dependency is required; this is native JNDI functionality.

## Behaviour changes

- The filter expression is now parameterized and does not require manual escaping.
- String arguments passed via the `filterArgs` parameter are automatically escaped per RFC 4515 by the JNDI provider before constructing the LDAP request.
- The search result enumeration is returned identically, so iteration and result handling are unchanged.
- If `data` contains LDAP metacharacters (e.g., `*`, `(`, `)`), they are now safely escaped and treated as literal values rather than query syntax.
