## Verdict

exploitable (confidence: high)

- CWE-90 - Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
- Location: `BenchmarkTest00012.java:69`, `idc.search(base, filter, filters, sc)`

## Source

`request.getHeaders("BenchmarkTest00012")` (line 45) - the first value of the `BenchmarkTest00012` HTTP header, fully attacker-controlled. It is URL-decoded at line 52 (`java.net.URLDecoder.decode(param, "UTF-8")`), which does not neutralize LDAP filter metacharacters - it only reverses percent-encoding, so a raw `*`, `(`, `)`, or `\` in the header, or a percent-encoded one, reaches `param` unescaped either way.

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
            String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
            Object[] filters = new Object[] {param, "The streetz 4 Ms bar"};

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

The vulnerable filter concatenated the raw, attacker-controlled `param` directly into the `uid=` clause of the LDAP filter string, so any `*`, `(`, `)`, or `\` in the request header could close the `uid` term and open a new one, altering the query's logic (e.g. turning it into a wildcard that matches every entry, or injecting an `OR` branch). The existing `street={0}` placeholder in the same filter already shows the codebase has JNDI's parameterized search available; the fix extends the same mechanism to `uid` by giving it its own placeholder, `{0}`, and passing `param` as the first element of the `filters` array (shifting the existing street literal to `{1}`). `DirContext.search(Name, String, Object[], SearchControls)` substitutes each `{i}` placeholder with the corresponding `filterArgs[i]`, and because both arguments are typed as `String`, the JDK encodes them per RFC 4515 (escaping `*`, `(`, `)`, `\`, and NUL) before they reach the filter - the same call, but the value can no longer break out of its clause. No other line changes: the sink is still `idc.search(base, filter, filters, sc)` with the same four arguments in the same order, `sc` and `base` are untouched, and the ESAPI HTML-encoding on the response output (already correct for the CWE-90 concern, not part of the fix) is unchanged.

## Behaviour changes

- `filter` string: `uid=` + concatenated `param` replaced with `uid={0}` - `param` is no longer interpolated as raw filter syntax but substituted via JNDI's own placeholder mechanism and RFC-4515-escaped. This is the fix itself, not a side effect.
- `filters` array: `param` prepended as the new `filters[0]`, shifting the existing street literal `"The streetz 4 Ms bar"` to `filters[1]` to match its new `{1}` placeholder. Required so the placeholder indices stay aligned; the street literal's value and position in the query are otherwise unchanged.
- Return value, exception handling, response content-type, search scope (`sc`), search base, output formatting, and the ESAPI HTML-encoding of results are all unchanged.
- For a `param` value with no LDAP metacharacters, query semantics and output are identical to the original. For a `param` value containing `*`, `(`, `)`, `\`, or NUL, the value is now matched literally against `uid` instead of altering the filter's structure - this is the intended closure of the injection, not a functional regression for legitimate usernames.
- No change to search scope, bind account, or attribute restriction - those remain out of scope for this fix (defence-in-depth, not required to close this finding).

## Verification

Copied the file to a scratch directory (outside the repo and outside the case directory) and ran `javac` on the fixed version. The compiler reported errors only for pre-existing external dependencies not on the ad hoc classpath (`javax.servlet.*`, `org.owasp.esapi.*`, `org.owasp.benchmark.helpers.LDAPManager`) - the same classes the original, unmodified file also fails to resolve without the project's full classpath. No error was reported against the changed lines (`filter`, `filters`, or the `idc.search(...)` call itself); `javax.naming.directory.DirContext.search(Name, String, Object[], SearchControls)` is a JDK-standard four-argument overload already used unmodified at the sink, so only its arguments changed, not the call shape. `filters` and `filter` are pre-existing local variables (not new names), so no new symbol needed introduction or verification.

## Assumptions

None - the fix reuses the parameterized-search mechanism already present in the same filter string (`street={0}`) and requires no new imports, dependencies, or ambiguity resolution.
