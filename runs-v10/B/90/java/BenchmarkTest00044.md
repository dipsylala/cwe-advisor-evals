## Verdict

CONFIRMED: CWE-90 LDAP Injection vulnerability exists at line 60. Untrusted user input from `request.getParameterValues()` is concatenated directly into an LDAP filter string without escaping, allowing attackers to inject LDAP filter metacharacters.

## Source

Lines 44-47: HTTP request parameter `BenchmarkTest00044` is extracted via `request.getParameterValues()` into variable `param` with no validation.

Line 56: The untrusted `param` is directly concatenated into the LDAP filter: `"(&(objectclass=person)(uid=" + param + "))"`.

Line 60: The concatenated filter is passed to `ctx.search(base, filter, sc)`, which executes the LDAP search.

## Fix

Replace line 56 and line 60 with parameterized filter:

**Line 56 - change from:**
```
String filter = "(&(objectclass=person)(uid=" + param + "))";
```

**Line 56 - change to:**
```
String filter = "(&(objectclass=person)(uid={0}))";
```

**Line 60 - change from:**
```
ctx.search(base, filter, sc);
```

**Line 60 - change to:**
```
ctx.search(base, filter, new Object[]{param}, sc);
```

Complete fixed code block for lines 54-60:
```java
javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
String filter = "(&(objectclass=person)(uid={0}))";
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, new Object[]{param}, sc);
```

## Explanation

The fix uses JNDI's parameterized `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload. By passing the user input via the `filterArgs` parameter instead of concatenating it into the filter string, JNDI automatically escapes the value according to RFC 4515 before constructing the LDAP query. This prevents special LDAP characters (`*`, `(`, `)`, `\`, NUL) from being interpreted as query syntax. The placeholder `{0}` in the filter string marks where the first argument should be substituted. The existing `SearchControls` object `sc` is reused as the fourth parameter. This closes the injection vector while maintaining the same query functionality.

## Behaviour changes

- Query result set remains identical for valid, non-malicious input.
- Special LDAP characters in the `uid` parameter are now escaped rather than interpreted as filter syntax.
- Injection payloads (e.g., `uid=*`, `uid=*)`, `uid=*)(|(uid=*`) are treated as literal string values in the uid attribute and will not modify the filter logic.
- No change to how results are displayed, exception handling, or the LDAP connection lifecycle.
