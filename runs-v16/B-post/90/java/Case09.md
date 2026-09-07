## Verdict

True positive. Untrusted HTTP input flows through a five-method call chain (Case09A → Case09B → Case09C → Case09D → Case09E) into an LDAP filter string constructed by direct concatenation at line 31 of Case09E.java, then passed to `DirContext.search()` at line 33 without any escaping.

## Source

**Injection point:** Line 31 of Case09E.java, where `data` (from `request.getParameter("name")`) is directly concatenated into the filter string:
```java
String search = "(cn=" + data + ")";
```

**Data flow:**
1. Case09A: `request.getParameter("name")` captures untrusted HTTP input
2. Case09B, Case09C, Case09D: Pass the data through intermediate methods
3. Case09E: Concatenate into filter and pass to sink

**Sink:** Line 33, `directoryContext.search("", search, null)` executes the LDAP query with the attacker-controlled filter.

## Fix

Replace string concatenation with JNDI's parameterized search filter method, which automatically escapes filter arguments per RFC 4515.

**Replace lines 31–33:**

Original:
```java
String search = "(cn=" + data + ")";
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

With:
```java
String filterExpr = "(cn={0})";
Object[] filterArgs = new Object[] { data };
SearchControls cons = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, cons);
```

## Explanation

JNDI's parameterized `search()` overload takes filter arguments separately from the filter expression template. When a string-valued argument is passed via the `filterArgs` array, JNDI's provider escapes it according to RFC 4515, encoding the LDAP metacharacters (`*`, `(`, `)`, backslash, and NUL) so they cannot modify the filter structure. The filter expression itself remains constant, preventing injection. The explicit `SearchControls` object replaces the null argument, providing clearer intent and correct scope handling.

## Behaviour changes

- Filter metacharacters in the user-supplied data are now escaped, preventing filter injection
- The filter structure is fixed and cannot be altered by attacker input
- Injection payloads like `*`, `)`, `(`, or LDAP filter operators are treated as literal string values within the cn attribute, not as filter syntax
- `SearchControls` is now instantiated explicitly instead of passing null (better practice; default scope remains unchanged)
- Return type and error handling are unchanged
