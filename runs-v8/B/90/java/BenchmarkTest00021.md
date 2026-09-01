## Verdict

Exploitable. User-controlled request parameter flows unsanitized into LDAP filter string, allowing injection of filter metacharacters.

## Source

Line 44: `String param = request.getParameter("BenchmarkTest00021");`

Untrusted HTTP request parameter, passed directly to filter construction.

## Fix

**Before:**
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
    String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
    Object[] filters = new Object[] {"The streetz 4 Ms bar"};
    // ...
    javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
            ctx.search(base, filter, filters, sc);
```

**After:**
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
    String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
    Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};
    // ...
    javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
            ctx.search(base, filter, filters, sc);
```

## Explanation

The fix replaces string concatenation with parameterized filter arguments. By replacing the concatenated `param` in the filter string with a placeholder `{0}` and moving the user input to the `filterArgs` array as the first element, JNDI's `DirContext.search()` method will apply RFC 4515 escaping to the parameter automatically. This escaping neutralizes LDAP metacharacters (`*`, `(`, `)`, `\`, and NUL) that could otherwise modify filter logic and allow attackers to bypass authentication, extract unauthorized directory data, or manipulate search results. The second placeholder `{1}` is added for the hardcoded street value to maintain consistent parameterization.

## Behaviour changes

The filter string no longer uses string concatenation for user input; instead, both `param` (user-controlled) and the hardcoded street value are passed through the `filterArgs` parameter where JNDI applies RFC 4515 escaping. The search results are identical; the change only affects how untrusted input is passed to the underlying LDAP operation, making it safe from injection. No arguments are added beyond those already present, and the return value and error handling remain unchanged.
