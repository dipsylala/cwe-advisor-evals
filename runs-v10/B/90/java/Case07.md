## Verdict

Confirmed. LDAP Injection vulnerability is exploitable. Untrusted user input from `request.getParameter("name")` is concatenated directly into an LDAP filter string with no escaping or parameterization, allowing injection of LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify query logic and access unauthorized directory data.

## Source

- **Flow origin**: `request.getParameter("name")` in Case07A.java, line 16
- **Intermediate**: Passed as `data` parameter to `Case07B.handleSink()` in Case07A.java, line 18
- **Sink**: `directoryContext.search("", search, null)` in Case07B.java, line 32
- **Vulnerability point**: `String search = "(cn=" + data + ")"` in Case07B.java, line 29

The user input flows unescaped from HTTP request parameter → method argument → LDAP filter string concatenation → JNDI search sink.

## Fix

Replace the concatenated filter string with JNDI's parameterized `search()` overload:

**Vulnerable code (Case07B.java, lines 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
Object[] filterArgs = { data };

NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, new SearchControls());
```

## Explanation

The fix uses JNDI's parameterized search filter overload, which accepts placeholder arguments separately via the `filterArgs` parameter. The JDK automatically escapes string-valued arguments per RFC 4515, neutralizing LDAP metacharacters before they reach the directory service. The data is no longer part of the filter structure; it is treated as data only. The `new SearchControls()` argument is required because this overload signature mandates a `SearchControls` parameter; using the default values preserves the existing search scope behavior.

## Behaviour changes

**Legitimate searches:** Unchanged. Searches for users whose CN matches the input parameter continue to work as before. For example, a search for "alice" returns the same results with both the vulnerable and fixed code.

**Attack attempts:** Blocked. An attacker attempting `alice*` to query with a wildcard, or `alice)(|(cn=*)` to inject an OR clause, will no longer modify the filter structure. The injected characters are escaped by JNDI and treated as literal filter value bytes, so no additional entries are returned and no privilege bypass occurs.

**Error handling:** Unchanged. `NamingException` is still thrown and caught by the same handler if the directory service is unavailable.

**No functional regressions**: The fix does not alter the return type, exception contract, or caller's iteration logic over results.
