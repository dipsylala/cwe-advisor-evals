## Verdict

Exploitable. Untrusted user input from the HTTP request parameter is concatenated directly into an LDAP filter string and passed to `DirContext.search()` without escaping.

## Source

Line 44: `request.getParameterValues("BenchmarkTest00044")` retrieves untrusted user input. The value flows to line 46 where it is assigned to `param`, then to line 56 where it is concatenated into the LDAP filter string.

## Fix

**Vulnerable code (lines 56–60):**
```java
String filter = "(&(objectclass=person)(uid=" + param + "))";
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, sc);
```

**Fixed code:**
```java
String filter = "(&(objectclass=person)(uid={0}))";
Object[] filterArgs = {param};
boolean found = false;
javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
        ctx.search(base, filter, filterArgs, sc);
```

## Explanation

The fix replaces string concatenation with JNDI's parameterized `search()` overload. Instead of building the filter string by concatenating untrusted input, a placeholder `{0}` is used in the filter template, and the user input is passed separately via the `filterArgs` parameter as an `Object[]`. The JNDI framework automatically escapes each argument in the array according to RFC 4515, neutralizing LDAP metacharacters (`*`, `(`, `)`, `\`, and NUL) before the filter is sent to the directory server. This ensures the filter structure cannot be modified by an attacker.

## Behaviour changes

None. The fix uses the 4-argument `search(String name, String filterTemplate, Object[] filterArgs, SearchControls cons)` overload instead of the 3-argument version. Both perform the same logical search and return the same results; the parameterized version adds automatic escaping, the only functional change being that the filter argument is now safe from injection.
