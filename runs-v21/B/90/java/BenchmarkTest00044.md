## Verdict

Real vulnerability confirmed. Untrusted user input from request parameters is concatenated directly into an LDAP filter string without escaping, allowing LDAP injection attacks.

## Source

Line 44-47: Request parameter values are extracted into `param` without validation.
Line 56: LDAP filter is constructed by string concatenation with untrusted `param`.
Line 60: The concatenated filter is passed to `ctx.search()`, reaching the LDAP directory.

Attack scenario: If user supplies `*` as parameter, the filter becomes `(&(objectclass=person)(uid=*))` which matches all users. If user supplies `uid=admin)(|(uid=`, query structure is broken to bypass authorization.

## Fix

Replace string concatenation with JNDI's parameterized `search()` overload. Use `{0}` placeholder in filter and pass user input via `filterArgs` parameter. JNDI will escape RFC 4515 metacharacters (`*`, `(`, `)`, `\`, NUL) automatically.

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

The fix replaces the vulnerable string concatenation with JNDI's parameterized `search()` method. Line 56 changes from `"(&(objectclass=person)(uid=" + param + "))"` to `"(&(objectclass=person)(uid={0}))"`—a template with a placeholder. Line 57 introduces `Object[] filterArgs = {param}` to hold the untrusted value separately. Line 59 changes the `search()` call from the 3-argument overload to the 4-argument overload: `ctx.search(base, filter, filterArgs, sc)`.

When JNDI processes this 4-argument form, it automatically escapes `String` values in `filterArgs` according to RFC 4515, neutralizing LDAP metacharacters. If user supplies `*`, it is escaped to `\2a` in the search; if user supplies `uid=admin)(|(uid=`, the parentheses and equals are escaped, making them literal characters rather than LDAP operators. The filter structure remains under application control, and user input cannot alter query logic.

## Behaviour changes

- **Filter construction**: Changed from string concatenation to parameterized placeholder and arguments array.
- **JNDI call signature**: Changed from 3-argument `search(name, filter, controls)` to 4-argument `search(name, filterExpr, filterArgs, controls)`.
- **Escaping**: LDAP metacharacters in user input are now escaped by JNDI before reaching the directory.
- **Functional outcome**: Queries still execute as intended; legitimate values (including special characters) are escaped and matched literally; malicious LDAP injection attempts are neutralized.
