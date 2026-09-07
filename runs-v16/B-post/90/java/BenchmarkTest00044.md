## Verdict

**Confirmed - LDAP Injection Vulnerability**

CWE-90 vulnerability confirmed at line 60. The LDAP search filter is constructed by concatenating untrusted user input directly into the query string, allowing attackers to inject LDAP filter syntax to manipulate directory searches.

## Source

- **Parameter source**: `request.getParameterValues("BenchmarkTest00044")` (line 44)
- **Assignment to variable**: `param` (lines 44-47)
- **Concatenation point**: Line 56 builds the filter string by direct concatenation: `String filter = "(&(objectclass=person)(uid=" + param + "))";`
- **Taint sink**: Line 60 passes the concatenated filter to `ctx.search(base, filter, sc)`

The attacker-controlled `param` value flows directly into the LDAP filter without any escaping or validation, reaching the JNDI `DirContext.search()` method.

## Fix

**Replace the filter construction and search call:**

**Before (vulnerable):**
```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, sc);
```

**After (fixed):**
```java
String filter = "(&(objectclass=person)(uid={0}))";
Object[] filterArgs = {param};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filterArgs, sc);
```

## Explanation

The fix uses JNDI's parameterized search method, which treats filter arguments as separate from the filter expression string. By passing `param` via the `filterArgs` parameter instead of concatenating it into the filter string, JNDI automatically applies RFC 4515 escaping to neutralize LDAP metacharacters (`*`, `(`, `)`, `\`, NUL).

The filter template uses `{0}` as a placeholder for the first argument, which JNDI replaces with the properly escaped value. This separates query structure from user data, preventing injection attacks. The 4-argument `search(name, filterExpr, filterArgs, cons)` overload must be used when `filterArgs` is provided.

## Behaviour changes

- **Filter argument escaping**: JNDI automatically escapes special LDAP characters in the `param` value, preventing filter injection while preserving the intended search semantics.
- **Query structure**: The filter structure (`"(&(objectclass=person)(uid={0}))"`) remains under developer control and is not affected by user input.
- **Return type unchanged**: The call still returns `javax.naming.NamingEnumeration<SearchResult>`, and result iteration proceeds as before.
- **Exception handling unchanged**: JNDI still throws `NamingException` on directory errors; existing catch blocks at line 94 remain valid.
- **No behavioral change to the search**: A legitimate `uid` value like `alice` is now passed as an escaped argument instead of being concatenated, but JNDI's RFC 4515 escaping is transparent for ASCII alphanumeric values - the search behavior for normal inputs is identical.
