## Verdict

Confirmed. Exploitable LDAP injection.

## Source

`request.getParameterValues("BenchmarkTest00044")` in `doPost` (line 44) - the first value is taken unvalidated into `param`.

## Fix

Data flow: `param` (attacker-controlled) is concatenated directly into the LDAP search filter string `filter` (line 56), which is passed unmodified to `ctx.search(base, filter, sc)` (line 60, the `DirContext.search(Name/String, String, SearchControls)` overload). A value such as `*)(uid=*))(|(uid=*` closes the `uid` clause and injects an always-true alternation, and a bare `*` turns the equality test into a wildcard that matches every `person` entry - either lets an attacker enumerate or dump directory records outside the intended single-user lookup.

Sink contract (`DirContext.search`):
- **Returns**: a `NamingEnumeration<SearchResult>`, iterated by the existing `while (results.hasMore())` loop.
- **Discards**: nothing beyond what the original code already ignored.
- **Arguments left implicit**: the 3-arg overload used here has no `filterArgs` slot at all - the fix does not add or omit an implicit argument, it moves to the 4-arg overload that has a `filterArgs` parameter for this exact purpose.
- **Failure behaviour**: throws `javax.naming.NamingException`, already caught and rewrapped as `ServletException` by the existing `catch` block - unchanged.

The fix replaces string concatenation with JNDI's parameterized filter overload: build the filter with a `{0}` placeholder and pass the user value through `filterArgs`, which the JDK escapes per RFC 4515 before substitution, so `)`, `(`, `*`, `\`, and NUL in `param` can no longer alter the filter's structure. This is the primary defence named in `cwe/90/java/INDEX.md` and requires no new dependency. The "nothing found" message still needs the literal query text for display; that string is built with `java.text.MessageFormat.format(filter, param)` (JDK standard library, `java.text`) purely for the HTML message and is never passed to `ctx.search`, then still run through the existing `ESAPI.encoder().encodeForHTML()` before being written to the response, so the informational text is unchanged and no new injection point is introduced. No library version change is required - the fix uses only JNDI (`javax.naming.directory.DirContext`, already in the JDK) and `java.text.MessageFormat` (JDK standard library).

Verification: `javac` was run against the modified file (copied to a scratch directory, not the fixture). It reported only pre-existing unresolved-dependency errors (`javax.servlet.*`, `org.owasp.esapi.*`, `org.owasp.benchmark.helpers.LDAPManager` - none available on this scratch classpath) identical in kind to what the original file would also produce outside the OWASP Benchmark build; no error was reported on the changed lines (the `ctx.search(base, filter, filterArgs, sc)` call or the `MessageFormat.format` call), confirming the 4-argument `DirContext.search` overload and `MessageFormat.format(String, Object...)` signatures are used correctly.

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
            // Filter uses a {0} placeholder; JNDI escapes filterArgs per RFC 4515 before
            // substitution, so untrusted input can no longer alter the filter's structure.
            String filter = "(&(objectclass=person)(uid={0}))";
            Object[] filterArgs = new Object[] {param};
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
                                        + org.owasp.esapi.ESAPI.encoder()
                                                .encodeForHTML(
                                                        java.text.MessageFormat.format(
                                                                filter, param)));
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

The vulnerable code built the LDAP search filter by concatenating `param` directly into the string (`"(&(objectclass=person)(uid=" + param + "))"`) and passed that string straight to `DirContext.search(base, filter, sc)`. Because none of `)`, `(`, `*`, or `\` in `param` were neutralized, an attacker could close the `uid` clause and append arbitrary additional filter terms, or supply a bare `*` to match every entry in the subtree.

The fix keeps the same query shape and the same 4-parameter search behaviour (base DN, search scope, iteration over `SearchResult`, exception handling) but moves the user value out of the filter string and into JNDI's `filterArgs` parameter, using the overload `DirContext.search(String name, String filterExpr, Object[] filterArgs, SearchControls cons)`. The JDK substitutes `{0}` with the RFC-4515-escaped form of `param` before the filter is parsed, so special LDAP filter metacharacters in the input are rendered as literal data rather than structural syntax - this is the "Primary Defence" prescribed in the Java-specific guidance (`cwe/90/java/INDEX.md`) precisely for this case, and requires no new library. The only other change is cosmetic: the "nothing found" message, which previously echoed the literal (already-injectable) filter string back to the user through `encodeForHTML`, now echoes the same text reconstructed via `MessageFormat.format(filter, param)` so the displayed message is unchanged even though `filter` itself is now a template rather than a complete string; this string is display-only and is never sent to the directory.

No allowlist was added: the guidance requires one only where the application defines the value's format (e.g. a fixed username policy), which this benchmark handler does not establish, so escaping via `filterArgs` is the complete and appropriate fix here.

## Behaviour changes

- The literal filter string is no longer constructed by concatenation; `DirContext.search` is now called via its 4-argument, `filterArgs`-taking overload instead of the 3-argument overload. Search semantics (base DN, `SUBTREE_SCOPE`, matched attributes) are unchanged.
- Values containing LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL) are now treated as literal data instead of filter syntax, so a `uid` value that happens to contain one of those characters (previously mis-parsed or exploitable) will now correctly fail to match rather than altering the query - this is the intended security fix, not a regression.
- The "nothing found" message text displayed to the user is unchanged in content (still shows the effective query with the submitted value, HTML-encoded); it is now produced via `MessageFormat.format` instead of direct string concatenation, with no user-visible difference.
