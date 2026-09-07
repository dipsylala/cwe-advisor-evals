## Verdict

Exploitable. Untrusted user input from an HTTP request header is passed as environment variables to Runtime.exec() without validation, allowing command injection.

## Source

Line 45-47: `param` extracted from HTTP request header `BenchmarkTest00007` (untrusted user-controlled data).

## Fix

### File: BenchmarkTest00007.java

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

@WebServlet(value = "/cmdi-00/BenchmarkTest00007")
public class BenchmarkTest00007 extends HttpServlet {

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
        if (request.getHeader("BenchmarkTest00007") != null) {
            param = request.getHeader("BenchmarkTest00007");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String cmd =
                org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                        this.getClass().getClassLoader());
        String[] args = {cmd};

        Runtime r = Runtime.getRuntime();

        try {
            // FIXED: CWE-78 - removed untrusted parameter from environment variables
            Process p = r.exec(args);
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
}
```

## Explanation

The vulnerability existed because untrusted user input from the HTTP request header was passed as environment variables to `Runtime.exec()`. Environment variables can be exploited if the executed process reads and uses them unsafely (e.g., in shell expansions, path operations, or command construction). The fix eliminates this injection point by removing the `argsEnv` parameter entirely and invoking `Runtime.exec(args)` with only the safe command string, preventing the attacker-controlled input from reaching the subprocess environment.

## Behaviour changes

Removed lines 55-56 (String[] argsEnv = {param}; and the associated array). Changed line 62 from `r.exec(args, argsEnv)` to `r.exec(args)`. This prevents the untrusted parameter from being passed to the subprocess. The subprocess now executes with inherited environment variables from the parent process rather than a modified environment containing untrusted input. This is a behavioral change, but it is necessary to close the command injection vulnerability; the original behavior of accepting arbitrary environment variables from user input is the security flaw.
