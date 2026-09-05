## Verdict
VULNERABLE

## Source
Line 46: `param` originates from `request.getParameterValues("BenchmarkTest00044")`, untrusted HTTP request data.

## Fix
Replace the concatenated filter string with a parameterized search using JNDI's `DirContext.search(String, String, Object[], SearchControls)` overload:

```java
// Line 56: OLD (vulnerable)
String filter = "(&(objectclass=person)(uid=" + param + "))";

// NEW (fixed)
String filterExpr = "(&(objectclass=person)(uid={0}))";
Object[] filterArgs = new Object[]{param};

// Line 58-60: OLD (vulnerable)
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, sc);

// NEW (fixed)
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filterExpr, filterArgs, sc);
```

## Explanation
The original code builds an LDAP filter by concatenating the user-supplied `param` directly into the filter string. An attacker can inject LDAP metacharacters such as `*`, `(`, `)`, and `\` to break out of the intended filter structure and manipulate the query. For example, `param = "*"` changes the filter to `(&(objectclass=person)(uid=*))`, matching any user; `param = "*))(|(uid=*"` creates multiple top-level filters.

The fix uses JNDI's parameterized `search()` overload, which accepts a filter expression with `{0}` placeholders and passes filter argument values in a separate `Object[]` array. The JNDI implementation automatically escapes each string argument according to RFC 4515, neutralizing all LDAP metacharacters. The placeholder `{0}` in the filter expression refers to the first argument in the `filterArgs` array, and JNDI handles the substitution and escaping internally.

## Behaviour changes
- **Before:** User input is concatenated directly into the LDAP filter, allowing injection of filter metacharacters to alter query logic.
- **After:** User input is passed as a separate parameter and automatically escaped by JNDI before reaching the directory server, preventing filter metacharacter injection while preserving the literal string value intended.
