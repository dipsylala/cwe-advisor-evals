## Verdict
exploitable

## Source
`request.getParameter("name")` in Case08A (line 16) → passed through Case08B and Case08C → Case08D parameter `data`

## Fix

**Vulnerable code (Case08D, lines 29-32):**
```java
String search = "(cn=" + data + ")";

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, null);
```

**Fixed code:**
```java
String search = "(cn={0})";
SearchControls controls = new SearchControls();
Object[] filterArgs = new String[]{data};

// SAST FINDING: CWE-90 (LDAP Injection) reported here. Sink is the next statement.
NamingEnumeration<SearchResult> answer = directoryContext.search("", search, filterArgs, controls);
```

## Explanation
The vulnerability occurs when untrusted input from `request.getParameter("name")` is concatenated directly into an LDAP filter string without escaping, allowing LDAP injection attacks. An attacker could inject filter syntax (e.g., `*`, `)(`, `(|`) to modify the query logic and access unauthorized directory data.

The fix replaces string concatenation with JNDI's parameterized query API. The `DirContext.search(name, filterExpr, filterArgs, cons)` overload accepts filter arguments separately via the `filterArgs` parameter, and the JDK automatically escapes each string argument according to RFC 4515 before substituting it into the placeholder `{0}`. This ensures the user input is treated as data, not filter structure. The `SearchControls` object provides required configuration (default scope is sufficient for this case).

## Behaviour changes
**SearchControls instantiation added:** A new `SearchControls()` object is created and passed to the search call. The original code passed `null` as the fourth argument, relying on JNDI defaults. The default `SearchControls` applies the same scope and behavior; this change introduces no functional difference—only the explicit object makes the parameterized API required. If custom search scope or attribute restrictions were needed, they would be set on this object, but the default is appropriate here.

**filterArgs array added:** User input now travels through the `filterArgs` parameter instead of direct concatenation. This changes where escaping occurs (in JNDI, not in the application code), but the data still reaches the same LDAP server operation. The escape set (RFC 4515: `*`, `(`, `)`, `\`, NUL) is applied automatically and completely—partial escaping is not possible with this API.

**No return value or exception behavior change:** The search call signature remains the same; it returns the same `NamingEnumeration<SearchResult>` and throws the same exceptions as before.
