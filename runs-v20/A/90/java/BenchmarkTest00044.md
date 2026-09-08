## Verdict

Confirmed. `param` comes from `request.getParameterValues("BenchmarkTest00044")` (attacker-controlled) and is concatenated directly into an LDAP search filter string, which is then passed to `DirContext.search()`. An attacker can inject LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) to alter the filter's logic - for example widening the match beyond the intended `uid` or short-circuiting the filter with an always-true clause.

## Source

`request.getParameterValues("BenchmarkTest00044")` in `doPost` (line 44), flowing unmodified into `param`, which is concatenated into the `filter` string at line 56 and reaches the sink at line 60 (`ctx.search(base, filter, sc)`).

## Fix

### File: BenchmarkTest00044.java

```java
/**
 * OWASP Benchmark v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
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
            String safeParam = org.owasp.esapi.ESAPI.encoder().encodeForLDAP(param);
            String filter = "(&(objectclass=person)(uid=" + safeParam + "))";
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    ctx.search(base, filter, sc);
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

The fix encodes the attacker-controlled value with ESAPI's `Encoder.encodeForLDAP(String)` before it is concatenated into the filter string. This escapes the LDAP filter metacharacters defined by RFC 4515 (`*`, `(`, `)`, `\`, and NUL) to their `\XX` hex-escaped form, so the value can only ever match as a literal `uid` value inside the existing `(uid=...)` clause - it can no longer inject additional filter clauses, wildcard the match, or terminate the expression early. The rest of the data flow, the search call, result handling, and the existing HTML-output encoding via `ESAPI.encoder().encodeForHTML()` are unchanged. ESAPI is already a project dependency (used for HTML output encoding in this same file), so no new dependency is introduced.
