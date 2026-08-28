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
            // The user-supplied uid is now a placeholder, not concatenated syntax.
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
The `BenchmarkTest00021` request parameter was concatenated directly into the LDAP search filter, so its characters were parsed as filter syntax: a value like `*)(uid=*))(|(uid=*` would terminate the uid term, add attacker-chosen clauses, and broaden the search to every entry under the base DN. The uid value is now supplied as a `{1}` placeholder and passed in the `filterArgs` array to the parameterized `DirContext.search(String, String, Object[], SearchControls)` overload already in use for the hard-coded street value. The JDK escapes each argument to RFC 4515 before substitution, so the filter's structure comes only from the literal template and the untrusted parameter can never be interpreted as LDAP metacharacters. The no-results branch now echoes only the placeholder template, keeping request data out of the response as well.
