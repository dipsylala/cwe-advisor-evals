## Verdict

Exploitable. OS command injection via shell metacharacter interpretation in user input passed to ProcessBuilder.

## Source

Line 46: `param = request.getHeader("BenchmarkTest00006");` - HTTP header sourced from request, fully attacker-controlled. URL-decoded at line 50 but not sanitized for shell metacharacters.

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
            // Output the parameter directly without using system commands
            response.getWriter().println(param);
        } catch (IOException e) {
            System.out.println(
                    "Problem writing output - BenchmarkTest00006 Test Case");
            throw new ServletException(e);
        }
    }
}
```

## Explanation

The vulnerability arises from concatenating untrusted user input directly into a shell command string (`"echo " + param`), then executing that string via `ProcessBuilder` with shell invocation (`sh -c` or `cmd.exe /c`). This allows an attacker to inject shell metacharacters (`;`, `|`, `&`, `$()`, etc.) to execute arbitrary commands. For example, if the attacker supplies `; rm -rf /` as the header value, the resulting command becomes `sh -c "echo ; rm -rf /"`, executing both echo and rm. The fix eliminates OS command execution entirely by outputting the parameter directly using Java's response writer, which is the appropriate solution when the purpose of the code is simply to output data rather than to execute a command as a feature. This removes the attack surface completely without requiring input validation or safer command execution APIs.

## Behaviour changes

**Removed ProcessBuilder code path**: The original code created an ArrayList, instantiated ProcessBuilder, invoked it with a shell and concatenated command string, and captured process output through a Utils helper function. The fixed code uses only `response.getWriter().println(param)` to write output. The result for the calling code is identical—the parameter value followed by a newline is written to the HTTP response body—but without spawning a child process or invoking a shell. No error handling changes required; IOException from response.getWriter() is still caught and re-thrown as ServletException, preserving the original exception contract.
