## Verdict

Confirmed. The LDAP search filter at line 54/59 is built by concatenating the raw `BenchmarkTest00021` request parameter directly into the filter string, then passed to `DirContext.search()`. An attacker who controls that parameter can inject LDAP filter metacharacters (`)`, `(`, `*`, `\`, null) to alter the search filter's structure - broadening the query, short-circuiting the intended clause, or extracting data the filter was meant to exclude.

## Source

`request.getParameter("BenchmarkTest00021")` at line 44, assigned to `param` (defaulted to `""` if absent). This value flows unmodified into the filter string built at line 54 and is searched at line 59:

```
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
...
ctx.search(base, filter, filters, sc);
```

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
            String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);
            String filter = "(&(objectclass=person))(|(uid=" + safeParam + ")(street={0}))";
            Object[] filters = new Object[] {"The streetz 4 Ms bar"};
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
}
```

## Explanation

`org.owasp.esapi.ESAPI.encoder().encodeForLDAP(String)` escapes the characters that are meaningful inside an LDAP search filter (`\`, `*`, `(`, `)`, and the NUL byte) per RFC 4515, turning them into their `\XX` hex-escaped form. Applying it to `param` before it is concatenated into `filter` means any filter metacharacters the attacker supplies are treated as literal characters to match against the `uid` attribute rather than as filter syntax, so the attacker can no longer alter the structure of the query (e.g. close the `uid=` clause early, inject an `OR`/wildcard, or append additional filter terms).

ESAPI is already a project dependency here - it is used for `encodeForHTML()` on the output path - so this fix adds no new dependency, only a second call against the same encoder for the input path. The second placeholder-substituted clause (`street={0}`) was already safe: `DirContext.search(base, filter, filters, sc)`'s array-argument overload does its own JNDI-level escaping for the `{0}` substitution, so that clause needed no change.
