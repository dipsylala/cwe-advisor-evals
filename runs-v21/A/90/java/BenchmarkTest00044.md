## Verdict

**CONFIRMED**: CWE-90 (LDAP Injection) at line 60.

The vulnerability occurs at line 56 where an LDAP search filter is constructed by string concatenation with untrusted user input (`param`), then passed to `ctx.search()` at line 60 without any encoding or parameterization.

## Source

**File**: BenchmarkTest00044.java  
**Line**: 56 (filter construction), 60 (sink: `ctx.search()`)  
**Issue**: LDAP filter built by concatenating user-controlled request parameter

```
String filter = "(&(objectclass=person)(uid=" + param + "))";
```

The `param` value originates from `request.getParameterValues("BenchmarkTest00044")` (line 44) and flows unsanitized into the LDAP filter. An attacker can inject LDAP metacharacters (e.g., `*`, `(`, `)`) to manipulate the search logic and bypass access controls.

## Fix

Use JNDI's parameterized `DirContext.search()` method with placeholder arguments. Replace the concatenated filter string with a parameterized filter expression and pass user input via the `filterArgs` parameter, which JNDI escapes automatically per RFC 4515.

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
            Object[] filterArgs = {param};
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

The fix uses JNDI's built-in parameterized search filter mechanism, which is the primary defense against LDAP injection:

1. **Replace concatenation with placeholders**: The filter string is changed from `"(&(objectclass=person)(uid=" + param + "))"` to `"(&(objectclass=person)(uid={0}))"`, where `{0}` is a placeholder for the first filter argument.

2. **Pass values via filterArgs parameter**: User input is passed in the `filterArgs` array (`{param}`) rather than concatenated into the filter string.

3. **Use the correct DirContext.search() overload**: The method signature changes from `ctx.search(base, filter, sc)` to `ctx.search(base, filter, filterArgs, sc)`, invoking the parameterized variant.

JNDI automatically escapes values in the `filterArgs` array according to RFC 4515, neutralizing LDAP metacharacters such as `*`, `(`, `)`, and `\`. This prevents attackers from injecting filter syntax while preserving legitimate characters in the search value. The fix requires no external dependencies and leverages the JDK's standard LDAP API.
