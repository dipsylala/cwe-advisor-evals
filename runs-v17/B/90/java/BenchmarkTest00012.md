## Verdict

CONFIRMED - LDAP Injection via unsanitized filter concatenation. Line 60 constructs an LDAP filter by concatenating the user-supplied `param` directly into the filter string. This concatenated filter is passed to `idc.search()` on line 69, where the untrusted input can alter the filter's logical structure and bypass authorization checks.

## Source

Untrusted input originates from the HTTP request header `BenchmarkTest00012` (line 45), extracted and URL-decoded to `param` (line 52). The value is then directly concatenated into the LDAP filter on line 60 without escaping or sanitization.

Data flow:
1. Request header → `param` (line 45-49)
2. URL-decode (line 52)
3. Concatenate into filter string (line 60)
4. Pass to JNDI search sink (line 69)

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
            Object[] filterArgs = new Object[] {param, "The streetz 4 Ms bar"};

            javax.naming.directory.DirContext ctx = ads.getDirContext();
            javax.naming.directory.InitialDirContext idc =
                    (javax.naming.directory.InitialDirContext) ctx;
            boolean found = false;
            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    idc.search(base, filter, filterArgs, sc);
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

The fix replaces string concatenation with JNDI's parameterized filter API. The vulnerable code built the filter by concatenating `param` directly:

```java
String filter = "(&(objectclass=person))(|(uid=" + param + ")(street={0}))";
Object[] filters = new Object[] {"The streetz 4 Ms bar"};
idc.search(base, filter, filters, sc);
```

The corrected code uses placeholders `{0}` and `{1}` and passes the user input through the `filterArgs` parameter:

```java
String filter = "(&(objectclass=person))(|(uid={0})(street={1}))";
Object[] filterArgs = new Object[] {param, "The streetz 4 Ms bar"};
idc.search(base, filter, filterArgs, sc);
```

JNDI's `DirContext.search()` automatically escapes string arguments in the `filterArgs` array according to RFC 4515 (LDAP filter encoding), converting special characters (`*`, `(`, `)`, backslash, NUL) to their escaped forms. This separation of filter structure from data prevents an attacker from injecting LDAP syntax through the `param` value. The special characters that would alter filter logic—such as `)` to close the `uid` clause or `*` to convert equality to wildcard matching—are now treated as literal characters in the value being searched, not as filter operators.

## Behaviour changes

The escaping applied by JNDI's parameterized API is transparent to correct usage: legitimate values are still matched correctly, and error handling is unchanged. The only behavioural change is that characters with special meaning in LDAP filters (such as `*`, `(`, `)`, `\`) in the user's input are now treated as literal characters rather than filter syntax. For example, a user searching for a UID containing `*` will match the literal character, not function as a wildcard.
