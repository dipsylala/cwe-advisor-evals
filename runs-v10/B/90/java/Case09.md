## Verdict

**True Positive** — Untrusted user input flows through the call chain without validation and is concatenated into an LDAP filter string, which is then passed to `DirContext.search()` without escaping. An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query logic and access unauthorized directory data.

## Source

**Entry point:** Case09A.java, line 16 — `String data = request.getParameter("name");`

The untrusted parameter flows through:
- Case09A → Case09B (pass-through, line 18)
- Case09B → Case09C (pass-through, line 13)
- Case09C → Case09D (pass-through, line 13)
- Case09D → Case09E (pass-through, line 13)

**Sink:** Case09E.java, lines 29–32

Line 29 concatenates untrusted `data` into an LDAP filter:
```java
String search = "(cn=" + data + ")";
```

Line 32 passes the concatenated filter to `DirContext.search()`:
```java
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

## Fix

**Vulnerable code** (Case09E.java, lines 29–32):
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String filterExpr = "(cn={0})";
Object[] filterArgs = {data};

// LDAP filter arguments are now escaped per RFC 4515 by JNDI
NamingEnumeration<SearchResult> answer = directoryContext.search("", filterExpr, filterArgs, new SearchControls());
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized search filter overload. The filter expression uses a `{0}` placeholder, and the untrusted `data` is passed separately via the `filterArgs` array. JNDI automatically escapes each filter argument according to RFC 4515, neutralizing LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) before the filter reaches the directory server.

The `new SearchControls()` argument is required when using the `filterArgs` overload and applies default search scope and behavior. This approach enforces separation between query structure and user data, eliminating the injection vector while preserving the original query semantics.

## Behaviour changes

- **Return value:** Unchanged — `directoryContext.search()` still returns a `NamingEnumeration<SearchResult>`.
- **Exception handling:** Unchanged — `NamingException` is still thrown on error and caught at line 49.
- **Search scope and constraints:** Changed — the search now uses default `SearchControls()` instead of `null`. This applies the provider's default search scope (typically `SUBTREE_SCOPE`) instead of undefined behavior. If the original code relied on implicit defaults, this change makes them explicit and standard-compliant. If non-default scope was intended, it must be set on the `SearchControls` object before the search: `SearchControls controls = new SearchControls(); controls.setSearchScope(SearchControls.OBJECT_SCOPE); directoryContext.search("", filterExpr, filterArgs, controls);`
- **Security:** Escaping is now enforced by JNDI, preventing LDAP injection regardless of input content.
