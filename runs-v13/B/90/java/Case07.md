## Verdict

Confirmed exploitable. User-controlled input from `request.getParameter("name")` is concatenated directly into an LDAP filter string without escaping and passed to `DirContext.search()`, allowing filter injection attacks.

## Source

Data flow:
1. `Case07A.java`, line 16: `data = request.getParameter("name")` — untrusted HTTP parameter
2. `Case07A.java`, line 18: `(new Case07B()).handleSink(data, ...)` — passed to Case07B
3. `Case07B.java`, line 29: `String search = "(cn=" + data + ")"` — concatenated into filter
4. `Case07B.java`, line 32: `directoryContext.search("", search, null)` — filter passed to LDAP sink

Attack vector: An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the filter structure. For example, `name=*)(objectClass=*))(&(cn=` changes the filter from `(cn=VALUE)` to `(cn=*)(objectClass=*))(&(cn=`, bypassing authentication or returning unintended directory entries.

## Fix

Replace concatenation with parameterized filter syntax. Use the `DirContext.search()` overload that accepts `filterArgs` to separate query structure from user data:

```java
// Line 29-32: Replace this
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);

// With this
String filterExpr = "(cn={0})";
Object[] filterArgs = { data };
SearchControls cons = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, cons);
```

The parameterized overload `search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` escapes each filter argument according to RFC 4515, preventing the injected metacharacters from altering query structure.

## Explanation

The vulnerability exists because `String concatenation + data` treats user input as part of the query syntax, not as data. The parameterized `search()` method separates these concerns: the `filterExpr` provides the syntactic structure (`(cn={0})`), and `filterArgs` provides the data values. JNDI applies RFC 4515 escaping to each argument in `filterArgs`, converting metacharacters like `*`, `(`, `)` into escape sequences that are treated as literal characters, not query operators.

The `SearchControls` parameter is required when using the `filterArgs` overload; passing `new SearchControls()` applies default search scope and attribute selection. If the original code has specific scope or attribute requirements, those can be configured on the `SearchControls` object instead.

## Behaviour changes

- The filter now correctly treats user input as a DN attribute value, not as query syntax.
- Metacharacters in the `data` parameter are escaped and become literal, preventing injection.
- Search results are limited to entries with exact `cn` matches (after escaping); previously, a payload like `*` would match all entries with any `cn` value.
- The `SearchControls` object uses default settings (scope: SUBTREE_SCOPE, attributes: all, sizes and time limits: unlimited). If the original code's `null` SearchControls relied on different defaults or if specific scoping is needed, configure the object accordingly.
