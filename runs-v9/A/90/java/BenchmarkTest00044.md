## Verdict

Confirmed. User-controlled input is concatenated directly into an LDAP search filter without escaping, allowing LDAP filter injection.

## Source

`request.getParameterValues("BenchmarkTest00044")` at line 44 (via `doPost`, reached from `doGet`) — the first value is assigned to `param` at line 46 with no validation or encoding.

## Fix

```java
String[] values = request.getParameterValues("BenchmarkTest00044");
String param;
if (values != null && values.length > 0) param = values[0];
else param = "";

org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
try {
    response.setContentType("text/html;charset=UTF-8");
    javax.naming.directory.DirContext ctx = ads.getDirContext();
    String base = "ou=users,ou=system";
    javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
    sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
    String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);
    String filter = "(&(objectclass=person)(uid=" + safeParam + "))";
    boolean found = false;
    javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
            ctx.search(base, filter, sc);
    // ... rest unchanged
```

The only change is inserting `String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);` before the filter is built, and using `safeParam` instead of `param` in the filter string at line 56. Everything else in the method is unchanged.

## Explanation

`param` flows from an HTTP request parameter straight into the LDAP filter string `"(&(objectclass=person)(uid=" + param + "))"` (line 56), which is then passed unmodified to `ctx.search(base, filter, sc)` (line 60). Because none of the LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) are escaped, an attacker-supplied value can close the `uid` clause early and inject additional filter terms — for example broadening the match to return every record, or extending the boolean expression to probe other attributes (a classic LDAP filter injection / blind-LDAP-injection pattern).

The fix applies RFC 4515-compliant escaping to the untrusted value before it is embedded in the filter, using `ESAPI.encoder().encodeForLDAP()` — the same ESAPI encoder already used elsewhere in this file (for HTML output) is also present in this codebase's dependency set for LDAP context, so no new library is introduced. Escaping neutralizes the metacharacters by converting them to their literal, non-syntactic form (e.g. `*` becomes `\2a`), so the value can only ever match as a literal `uid`, never alter the structure of the filter. This preserves the search semantics for legitimate input while eliminating the injection: the attacker's string is treated purely as data, not as LDAP filter syntax. The rest of the data flow — the `DirContext` search call, result iteration, and HTML-encoding of the returned attributes on output — is unaffected and remains correct.
