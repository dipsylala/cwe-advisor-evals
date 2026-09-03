## Verdict

Exploitable. The `data` parameter is user-controlled (passed through the method signature) and is concatenated directly into an LDAP search filter without escaping at line 29, then passed to `DirContext.search()` at line 32. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query logic.

## Source

Case17A.java line 18: The `data` parameter passed to `Case17B.handleSink()`. Although the test case hardcodes "foo", the method signature accepts untrusted input.

## Fix

**Vulnerable code:**
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
Object[] filterArgs = new String[] { data };
SearchControls controls = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, controls);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized `DirContext.search()` overload, which takes a filter expression with placeholders (`{0}`, `{1}`, etc.) and a separate `filterArgs` array. The JNDI framework automatically escapes each string argument in the array per RFC 4515, neutralizing LDAP metacharacters. This separates query structure from user data at the API boundary. The `SearchControls` parameter is required for this overload; a default instance applies standard scope and attribute handling.

## Behaviour changes

- **SearchControls parameter added**: The call now includes `new SearchControls()` as the fourth argument. This is required by the parameterized overload; the defaults match the previous behavior of passing `null` to the three-argument overload (base object search, all user attributes, no limits).
- **No semantic changes to the query**: The filter expression `(cn={0})` with the parameterized value produces identical results to the original concatenated filter when `data` is safe, and correctly rejects injected syntax when `data` is malicious.
