## Verdict

Confirmed. LDAP injection (CWE-90).

## Source

`request.getParameter("name")` in `Case09A.handle()` (Case09A.java, line 16). The value is passed
unmodified through `Case09B.handleSink()` -> `Case09C.handleSink()` -> `Case09D.handleSink()` into
`Case09E.handleSink()`, where it is concatenated directly into an LDAP search filter and executed
against a directory context.

## Fix

In `Case09E.java`, replace the string-concatenated filter and the sink call:

```java
// Before (vulnerable)
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);

// After (fixed)
String filterExpr = "(cn={0})";
Object[] filterArgs = new Object[] { data };
NamingEnumeration<SearchResult> answer =
    directoryContext.search("", filterExpr, filterArgs, new SearchControls());
```

This uses the `DirContext.search(String name, String filterExpr, Object[] filterArgs,
SearchControls cons)` overload instead of `search(String name, String filter, SearchControls
cons)`. `SearchControls` must additionally be imported from `javax.naming.directory` (already the
same package as `DirContext`, so no new import is needed beyond instantiating it).

## Explanation

`data` originates from an HTTP request parameter, so it is fully attacker-controlled. Building the
filter with `"(cn=" + data + ")"` lets an attacker inject LDAP filter metacharacters (`*`, `(`,
`)`, `\`, NUL) to alter the search's logical structure - for example supplying
`*)(uid=*))(|(cn=*` to broaden or bypass the intended `cn` match, enumerate directory entries, or
short-circuit filter logic used elsewhere for access decisions.

The `search(String, String, Object[], SearchControls)` overload treats the filter string as a
template with positional placeholders (`{0}`, `{1}`, ...) per RFC 2254, and substitutes each
corresponding `filterArgs` element only after escaping the LDAP special characters within it. The
attacker-supplied value can therefore never break out of the `cn=...` position: any filter
metacharacters it contains are escaped to their literal representation rather than being
interpreted as filter syntax, so the query always searches for a `cn` whose literal value equals
`data`, regardless of its content.

The fix touches only the filter construction and the `search` call; the connection setup, result
iteration, and exception handling in the surrounding method are unchanged.
