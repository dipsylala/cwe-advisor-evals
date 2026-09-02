## Verdict

Confirmed. The LDAP search filter is built by directly concatenating an unvalidated, unescaped HTTP request parameter (`param`, from `request.getParameter("BenchmarkTest00021")`) into the filter string, then passed to `DirContext.search(...)`. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the query logic, bypass the intended `uid` match, or extract unintended directory data.

## Source

`String param = request.getParameter("BenchmarkTest00021");` (line 44), defaulted to `""` if null, then concatenated directly into the filter string at line 54:

```
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
```

This flows unescaped into the sink at line 59: `ctx.search(base, filter, filters, sc);`

## Fix

```java
String param = request.getParameter("BenchmarkTest00021");
if (param == null) param = "";

org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
try {
    response.setContentType("text/html;charset=UTF-8");
    javax.naming.directory.DirContext ctx = ads.getDirContext();
    String base = "ou=users,ou=system";
    javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
    sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
    // Use JNDI's built-in filter-argument substitution for BOTH user-influenced
    // values instead of string concatenation. DirContext.search(name, filterExpr,
    // filterArgs, cons) automatically encodes each {n} substitution per RFC 2254,
    // escaping *, (, ), \ and NUL so they can't alter the filter's structure.
    String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
    Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
    boolean found = false;
    javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
            ctx.search(base, filter, filters, sc);
    while (results.hasMore()) {
        javax.naming.directory.SearchResult sr =
                (javax.naming.directory.SearchResult) results.next();
        javax.naming.directory.Attributes attrs = sr.getAttributes();

        javax.naming.directory.Attribute attr = attrs.get("uid");
        javax.naming.directory.Attribute attr2 = attrs.get("street");
        if (attr != null) {
            response.getWriter()
                    .println(
                            "LDAP query results:<br>"
                                    + "Record found with name "
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(attr.get().toString())
                                    + "<br>Address: "
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(attr2.get().toString())
                                    + "<br>");
            found = true;
        }
    }
    if (!found) {
        response.getWriter()
                .println(
                        "LDAP query results: nothing found for query: "
                                + org.owasp.esapi.ESAPI.encoder().encodeForHTML(filter));
    }
} catch (javax.naming.NamingException e) {
    throw new ServletException(e);
} finally {
    try {
        ads.closeDirContext();
    } catch (Exception e) {
        throw new ServletException(e);
    }
}
```

## Explanation

The original code already uses JNDI's parameterized filter mechanism for the hardcoded `street` value (`{0}`), which relies on `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)` to safely encode each substituted argument according to RFC 2254 before it is inserted into the filter. The vulnerability is that `param`, the attacker-controlled value, bypasses this mechanism entirely and is concatenated directly into `filterExpr` as a literal string.

The fix extends the same substitution mechanism to the `uid` clause: `param` becomes the value bound to `{0}` and is passed through `filterArgs` rather than string-concatenated into the filter template. The JNDI provider escapes any LDAP filter metacharacters in the substituted value (parentheses, asterisks, backslashes, NUL), so an attacker cannot terminate the intended clause or inject additional filter logic. No other application behavior changes: the filter's semantics (an OR match on `uid` or `street`, ANDed with the `objectclass=person` constraint) are preserved, and the existing output encoding (`ESAPI.encoder().encodeForHTML`) for reflected attribute values is left in place as a secondary defense against stored data containing HTML-significant characters.
