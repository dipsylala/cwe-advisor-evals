## Verdict

exploitable

## Source

**File:** evals/cases/90/java/BenchmarkTest00021/BenchmarkTest00021.java

**Location:** Lines 44–45 (source), line 59 (sink)

**Untrusted input:** `param = request.getParameter("BenchmarkTest00021")` at line 44. The parameter value is extracted from an HTTP request with no validation.

**Data flow:** The `param` variable is concatenated directly into the LDAP filter string at line 54, then passed to `ctx.search()` at line 59. An attacker can inject LDAP metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the query logic.

**Exploitable path:** An attacker supplies `*)(uid=*))(&(objectclass=*` as the parameter value. This transforms the filter from `(&(objectclass=person))(|(uid=<param>)(street={0}))` into a form that bypasses the intended query structure and matches entries the attacker should not access.

## Fix

**Vulnerable code (line 54–55):**
```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
```

**Fixed code:**
```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
```

## Explanation

The vulnerability arises because user input (`param`) is concatenated directly into the LDAP filter string. LDAP filters are parsed as expression trees, so an attacker can inject special characters to restructure the query. The fix uses JNDI's parameterized `DirContext.search()` overload, which already appears in the code at line 59. By replacing the concatenated `param` with a placeholder `{0}` and passing `param` via the `filterArgs` Object array instead, JNDI's service provider automatically applies RFC 4515 escaping to the argument before substitution. This neutralizes LDAP metacharacters and prevents injection. The street value also moves from a hardcoded placeholder `{0}` to `{1}` to maintain correct positioning in the parameterized filter.

## Behaviour changes

- **Filter arguments now parameterized:** Both `param` and the street value are passed through the `filterArgs` array. JNDI escapes string-valued arguments per RFC 4515 before interpolating them into the filter.
- **Filter structure unchanged:** The base DN, search scope, and SearchControls object remain the same. The query still searches for `objectClass=person` entries with a UID or street attribute matching the provided values.
- **Return values unchanged:** Results are still enumerated in the same way; no change to how search results are processed or returned to the client.
- **No additional dependencies:** The fix uses only JNDI APIs already present in the code; no new libraries required.
