## Fix

```java
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

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
            // Untrusted input is bound as a filter argument, never concatenated into the filter.
            String filter = "(&(objectclass=person)(uid={0}))";
            Object[] filters = new Object[] {param};
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
    }
```

## Explanation

The first value of the `BenchmarkTest00044` request parameter was concatenated into the `uid` term of the search filter and handed to the three-argument `DirContext.search(name, filter, cons)`, which treats the whole string as filter syntax. A value such as `*)(objectClass=*` would close the `uid` clause and add an attacker-chosen one, and a bare `*` would match every person under `ou=users,ou=system`. The fix moves the search to the parameterized four-argument overload `ctx.search(base, filter, filters, sc)`: the filter is a fixed string with a `{0}` placeholder and the untrusted value travels separately in the `filters` array. JNDI parses the filter expression first and then substitutes each argument as an RFC 4515-escaped literal, so `(`, `)`, `\`, NUL and `*` in the input are compared as characters rather than acted on as filter operators, and the query structure is no longer attacker-controlled. The response's not-found path prints the constant filter, so no untrusted data is reflected back either.
