## Verdict

VULNERABLE. The code constructs an LDAP search filter by concatenating user-supplied input directly into the filter string without escaping, allowing LDAP injection.

## Source

- **Source**: `request.getParameter("name")` in Case07A.java, line 16
- **Flow**: Parameter passed to `Case07B.handleSink(data, ...)` in Case07A.java, line 18
- **Sink**: Concatenated into filter string in Case07B.java, line 29: `String search = "(cn=" + data + ")"`
- **Exploitation**: User can supply input like `*)(uid=*` to manipulate the LDAP filter structure and escape the intended equality test, matching all entries or accessing unauthorized attributes

## Fix

**Vulnerable code** (Case07B.java, lines 29-32):
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code**:
```java
String search = "(cn={0})";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, new Object[] { data }, new SearchControls());
```

## Explanation

The fix uses JNDI's parameterized `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` overload, which separates the filter structure from user data. The placeholder `{0}` marks where `data` will be substituted. JNDI automatically escapes string values in the `filterArgs` array according to RFC 4515, neutralizing LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) before they can alter the filter structure. The `SearchControls` object is required as the fourth parameter; `new SearchControls()` provides default scope and attribute handling matching the original call's intent.

## Behaviour changes

- The filter string now uses parameterized substitution instead of concatenation, preventing structural modification through special characters
- JNDI applies RFC 4515 escaping to the `data` value before substitution, so characters like `*`, `(`, and `)` are percent-encoded
- The method signature changes from `search(name, filterExpr, controls)` to `search(name, filterExpr, filterArgs, controls)`, requiring explicit `SearchControls` where the original code passed `null`; the new `SearchControls()` instance provides JNDI's default search scope (SUBTREE_SCOPE) and attribute selection (all), preserving the original behaviour
- No change to return value, error handling, or result iteration
