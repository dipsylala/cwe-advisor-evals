## Verdict

Exploitable

## Source

The `data` parameter received at line 17 in the method signature `public void handleSink(String data , HttpServletRequest request, HttpServletResponse response)` is attacker-controlled (derived from HTTP request input). It flows directly to an LDAP search filter via string concatenation.

## Fix

**Vulnerable code (line 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String searchFilter = "(cn={0})";
String[] filterArgs = { data };
SearchControls searchControls = new SearchControls();
NamingEnumeration<SearchResult> answer = directoryContext.search("", searchFilter, filterArgs, searchControls);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized `search()` overload. Instead of building the filter by concatenating untrusted `data` into the query string, the fix uses a placeholder `{0}` in the filter template and passes the user input as a separate `filterArgs` parameter. JNDI automatically escapes each argument according to RFC 4515 before substituting it into the filter, neutralizing LDAP metacharacters (`*`, `(`, `)`, backslash, NUL) that an attacker might inject. The `SearchControls` argument is required by this overload signature and supplies default search scope and constraints.

## Behaviour changes

- **Argument addition:** The `search()` call now passes `filterArgs` and `SearchControls`, replacing the previous `null` third argument. `SearchControls()` with no arguments sets the default scope (`SUBTREE_SCOPE`), which matches the original behaviour of an unbounded search.
- **Variable changes:** Two new variables (`searchFilter` and `filterArgs`) replace the concatenation, but the data flow and query semantics remain identical - the search still looks for entries where the `cn` attribute exactly matches the input value.
- **Return value:** Unchanged; `search()` still returns `NamingEnumeration<SearchResult>`.
