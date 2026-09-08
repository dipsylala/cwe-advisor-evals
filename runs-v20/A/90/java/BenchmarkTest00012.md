## Verdict

Confirmed. The value read from the `BenchmarkTest00012` request header (URL-decoded, fully attacker-controlled) is concatenated directly into an LDAP search filter string, which is then passed to `DirContext.search(...)`. An attacker can inject LDAP filter metacharacters (`)`, `(`, `*`, `\`, null) to alter the filter's logic, e.g. close the `uid=` clause early and append their own conditions, causing the search to return records it should not, or to always match.

## Source

`param` originates from `request.getHeaders("BenchmarkTest00012")` (first element) in `doPost`, then is URL-decoded via `java.net.URLDecoder.decode(param, "UTF-8")`. It flows unescaped into the filter string built at line 60 and reaches the sink at line 69 (`idc.search(base, filter, filters, sc)`).

## Fix

### File: BenchmarkTest00012.java

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

@WebServlet(value = "/ldapi-00/BenchmarkTest00012")
public class BenchmarkTest00012 extends HttpServlet {

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

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00012");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        org.owasp.benchmark.helpers.LDAPManager ads = new org.owasp.benchmark.helpers.LDAPManager();
        try {
            response.setContentType("text/html;charset=UTF-8");
            String base = "ou=users,ou=system";
            javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
            sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
            // Escape the untrusted value for use inside an LDAP search filter before
            // building the filter string, so filter metacharacters in the input
            // (parentheses, '*', '\', NUL) cannot alter the query's structure.
            String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);
            String filter = "(&(objectclass=person))(|(uid=" + safeParam + ")(street={0}))";
            Object[] filters = new Object[] {"The streetz 4 Ms bar"};

            javax.naming.directory.DirContext ctx = ads.getDirContext();
            javax.naming.directory.InitialDirContext idc =
                    (javax.naming.directory.InitialDirContext) ctx;
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    idc.search(base, filter, filters, sc);
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

The root cause is building the LDAP search filter by string concatenation of an untrusted value instead of encoding it for the LDAP filter context. `DirContext.search` has no parameterized-filter mechanism analogous to a prepared statement for the filter text itself (the `{0}` substitution array only applies to values already embedded via that placeholder syntax, and here the attacker-controlled value is concatenated directly rather than passed through it), so the standard remediation is contextual output encoding of the value before it is placed into the filter string.

The fix calls ESAPI's `Encoder.encodeForLDAP(String)` (`org.owasp.esapi:esapi`, already a project dependency here since it is used elsewhere in this file for HTML encoding) on `param` immediately before it is concatenated into `filter`. This method escapes the characters that are structurally significant in an RFC 4515 LDAP search filter - `(`, `)`, `*`, `\`, and NUL - so an attacker-supplied value such as `*)(objectclass=*` or `)(uid=*))(|(uid=*` is rendered as literal text matched against the `uid` attribute rather than being interpreted as filter syntax, closing off both filter-logic injection and blind LDAP injection via this parameter while leaving legitimate `uid` values (including ones containing normal punctuation) unaffected.

The `street={0}` clause is unaffected: its value is supplied through the separate `filters` array, which the JNDI API already substitutes as a literal attribute value rather than parsed filter syntax, so it was never part of this injection path and needs no change.
