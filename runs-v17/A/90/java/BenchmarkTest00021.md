## Verdict

CWE-90 vulnerability confirmed. The user-supplied parameter is directly concatenated into an LDAP filter without escaping, enabling filter injection attacks.

## Source

Line 44: User input retrieved from request parameter.
Line 54: User input concatenated directly into LDAP filter string.
Line 59: Unescaped filter passed to `ctx.search()`.

## Fix

### File: BenchmarkTest00021.java

```java
/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/ldapi-00/BenchmarkTest00021")
public class BenchmarkTest00021 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

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
            String filter = "(&(objectclass=person))(|(uid={1})(street={0}))";
            Object[] filters = new Object[] {"The streetz 4 Ms bar", param};
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    // SAST FINDING: CWE-90 (LDAP Injection) - an LDAP filter is built from request data and searched. Sink is the next statement.
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
}
```

## Explanation

The vulnerability occurs because `param` (user-supplied input) is concatenated directly into the LDAP filter string at line 54, without any escaping or parameterization. This allows attackers to inject LDAP filter syntax to alter the query logic.

The JNDI `DirContext.search()` method supports parameterized filter substitution using numbered placeholders `{0}`, `{1}`, etc. combined with an Object array. The original code already used this feature for the `street` attribute with placeholder `{0}`, but failed to use it for the `uid` attribute.

The fix changes:
- **Filter**: Changed from `"...uid=" + param + "..."` to `"...uid={1}..."` to use a placeholder
- **Filters array**: Expanded from `new Object[] {"The streetz 4 Ms bar"}` to `new Object[] {"The streetz 4 Ms bar", param}` to pass the user input safely through parameterized substitution

By using the parameterized API, the JNDI framework properly escapes LDAP metacharacters in the user input, preventing filter injection attacks. The attacker-controlled value is now treated as data rather than filter syntax.
