## Fix
```java
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = request.getParameter("BenchmarkTest00021");
        if (param == null) param = "";

        org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
        try {
            response.setContentType("text/html;charset=UTF-8");
            javax.naming.directory.DirContext ctx = ads.getDirContext();
            String base = "ou=users,ou=system";
            javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
            sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
            // Request data is bound as a filter argument ({1}) instead of being concatenated
            // into the filter expression, so JNDI escapes it as a literal assertion value.
            String filter = "(&(objectclass=person))(|(uid={1})(street={0}))";
            Object[] filters = new Object[] {"The streetz 4 Ms bar", param};
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
The request parameter was concatenated into the LDAP search filter, so filter metacharacters such as `)`, `(`, `*`, `&`, `|` and `\` allowed an attacker to terminate the `uid` assertion and inject additional filter components, changing which directory entries the search matched. The filter is now a constant expression whose only variable parts are the placeholders `{0}` and `{1}`, and the parameter is supplied through the `Object[]` argument array to `DirContext.search(String, String, Object[], SearchControls)`. JNDI parses the filter expression first and then substitutes each argument as an escaped literal assertion value, so untrusted input is treated as data rather than filter syntax and cannot alter the query's structure. The not-found response now echoes only the static placeholder filter instead of attacker-supplied text, and it stays HTML-encoded.
