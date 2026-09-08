## Verdict

exploitable

## Source

Line 45-46: `request.getHeader("BenchmarkTest00006")` - untrusted HTTP header value assigned to `param`

Line 50: `param = java.net.URLDecoder.decode(param, "UTF-8")` - decoding does not neutralize injection characters

## Sink

Line 70: `Process p = pb.start()` - ProcessBuilder executes a command constructed from untrusted input

## Fix

### File: BenchmarkTest00006.java

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

@WebServlet(value = "/cmdi-00/BenchmarkTest00006")
public class BenchmarkTest00006 extends HttpServlet {

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
        if (request.getHeader("BenchmarkTest00006") != null) {
            param = request.getHeader("BenchmarkTest00006");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        try {
            // FIXED: Eliminate OS command execution and use Java's built-in I/O instead
            response.getWriter().println(param);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
            throw new ServletException(e);
        }
    }
}
```

## Explanation

The original code constructs an OS command (`echo` with user-controlled input) via ProcessBuilder and executes it through a shell (`sh -c` or `cmd.exe /c`). Although using ProcessBuilder with argument lists is safer than string concatenation, the code still invokes a shell interpreter and concatenates untrusted input into the command string (`"echo " + param`), allowing shell metacharacter injection. An attacker could supply input like `test; cat /etc/passwd` or `test$(whoami)` to execute arbitrary commands.

The fix eliminates OS command execution entirely by replacing the shell invocation with Java's built-in servlet I/O API (`response.getWriter().println()`). Since the original code's sole purpose is to echo the user input back to the response, this native approach achieves the same result without any OS command injection risk. All imports, exception handling, and logging remain unchanged to preserve the original error handling contract.

## Behaviour changes

none

