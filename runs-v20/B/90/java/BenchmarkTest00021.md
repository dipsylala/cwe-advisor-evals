## Verdict

exploitable (confidence: high)

- cwe_id: CWE-90
- location: BenchmarkTest00021.java, line 59 (`ctx.search(base, filter, filters, sc)`)

## Source

`request.getParameter("BenchmarkTest00021")` (line 44), assigned to `param` (defaulted to `""` when absent, but otherwise fully attacker-controlled).

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
                    // Fixed: uid value is passed via the parameterized filterArgs
                    // ({1}) instead of being concatenated into the filter string, so
                    // JNDI escapes it per RFC 4515 before the search request is sent.
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

The filter template mixed two techniques: the `street` value already went through JNDI's parameterized `{0}` placeholder, but `uid` was still concatenated directly from `param` into the filter string, so an attacker-supplied `uid` value could inject LDAP filter metacharacters (`)`, `(`, `*`) and alter the query structure or turn it into a match-all. The fix removes the concatenation and gives `uid` its own placeholder, `{1}`, adding `param` as the second element of the `filters` array passed to `DirContext.search(base, filter, filters, sc)`. JNDI escapes each `String`-valued `filterArgs` entry per RFC 4515 before building the request, so any metacharacters in `param` are neutralized rather than parsed as filter syntax. The call still uses the same four-argument `search` overload with the existing `SearchControls`, so scope, returned attributes, and error handling (`NamingException` -> `ServletException`) are all unchanged.

## Behaviour changes

- `filter` string: `uid=` + concatenated `param` replaced with `uid={1}`. Reason: closes the injection point; this is the sink fix itself, not a side effect.
- `filters` array: gained a second element, `param`, mapped to the new `{1}` placeholder. Reason: required to supply the value for the added placeholder; no other element changed.
- No change to `base`, `sc`, the `search` overload used, loop logic, attribute handling, HTML encoding, or exception handling.
- Functional behaviour for legitimate input is preserved: a benign `param` value produces the same effective filter as before (JNDI substitutes `{1}` with the literal, escaped value of `param`, equivalent to the original concatenation for non-malicious strings).
- verification: Compiled the fixed file with `javac` (JDK 26) from a scratch copy outside the case directory. All reported diagnostics were pre-existing missing dependencies unrelated to the fix (`javax.servlet.*`, `org.owasp.esapi`, `org.owasp.benchmark.helpers.LDAPManager` are not on the classpath in this environment); no diagnostic was reported against the changed `filter`/`filters` lines or the `ctx.search(...)` call, confirming those lines type-check against the real JDK `DirContext.search(String, String, Object[], SearchControls)` signature.
- assumptions: none - the existing call already used the four-argument parameterized `search` overload with an explicit `SearchControls`, so no signature or overload change was needed; only the filter template and argument array required editing.
