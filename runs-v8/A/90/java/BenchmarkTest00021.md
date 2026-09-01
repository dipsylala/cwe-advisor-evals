## Verdict
CWE-90 (LDAP Injection) confirmed. User input from `request.getParameter()` is directly concatenated into an LDAP filter string without escaping, allowing filter syntax injection.

## Source
Line 44: `String param = request.getParameter("BenchmarkTest00021");` — untrusted user input.

Data flows directly into line 54: `String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";`

Sink at line 59: `ctx.search(base, filter, filters, sc)` — executes the attacker-modified filter.

## Fix
Replace string concatenation with parameterized filter placeholders. Move the `uid` parameter into the `filters` array and reference it by index:

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
    boolean found = false;
    javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
            ctx.search(base, filter, filters, sc);
```

## Explanation
LDAP filter syntax is interpreted by the directory server. Untrusted values concatenated into the filter string allow attackers to inject metacharacters like `*`, `(`, `)`, and `&` to modify the query logic — for example, input `*))(&(uid=admin` closes the uid filter early and injects arbitrary conditions.

Java's `DirContext.search()` method supports parameterized filters: the filter string contains `{0}`, `{1}` placeholders, and the `Object[]` array holds the actual values. The directory server treats all values in the array as literal data, not as filter syntax, automatically escaping any special characters.

The fix moves `param` from string concatenation into the `filters` array as index 0 and updates the filter template to use `{0}` for the uid placeholder instead of direct concatenation. This ensures the user input cannot alter the filter structure.
