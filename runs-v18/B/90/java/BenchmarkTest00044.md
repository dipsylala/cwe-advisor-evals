## Verdict

CONFIRMED: LDAP Injection via unsanitized user input concatenated into a filter string at line 56.

## Source

Line 44-47: User input is retrieved from `request.getParameterValues("BenchmarkTest00044")` without validation or escaping, stored in `param`.

Line 56: The `param` value is concatenated directly into an LDAP filter string: `"(&(objectclass=person)(uid=" + param + "))"`.

Line 60: The concatenated filter is passed to `ctx.search()`, allowing an attacker to inject LDAP filter syntax (e.g., `*`, `(`, `)`) to modify the query logic.

## Fix

Replace string concatenation of the filter with JNDI's parameterized `search()` overload, which accepts filter arguments separately and applies RFC 4515 escaping automatically.

### File: BenchmarkTest00044.java

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

@WebServlet(value = "/ldapi-00/BenchmarkTest00044")
public class BenchmarkTest00044 extends HttpServlet {

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
            String filter = "(&(objectclass=person)(uid={0}))";
            Object[] filterArgs = new Object[]{param};
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    ctx.search(base, filter, filterArgs, sc);
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

The vulnerability was caused by building an LDAP filter string via string concatenation with untrusted user input. An attacker could inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to modify the query logic—for example, `uid=*)(uid=*` would bypass authentication by making the filter always true.

The fix uses JNDI's parameterized `DirContext.search()` overload (line 60), which accepts:
1. A filter template with `{0}` placeholders instead of concatenated values
2. An `Object[]` array of filter arguments passed separately
3. A `SearchControls` object for configuration

JNDI's service provider automatically escapes each argument in the `Object[]` array according to RFC 4515 (LDAP filter escaping), preventing injection. The attacker-controlled `param` value is no longer parsed as filter syntax—special characters are escaped, and only the intended literal value is matched.

## Behaviour changes

- **Filter construction**: Changed from string concatenation to parameterized placeholders and argument array
- **Escaping**: JNDI now handles RFC 4515 escaping of the `param` value automatically, converting metacharacters to their escaped equivalents
- **Query logic**: Unaffected for legitimate inputs; injection payloads are neutralized and treated as literal search values
- **Performance**: Negligible; the parameterized API may enable query plan caching in the LDAP server
