## Verdict
VULNERABLE - CWE-78 (OS Command Injection)

## Source
Line 62 constructs a shell command by concatenating user-controlled input (`param`) directly into a command string without escaping or validation. When this command is executed via `sh -c` or `cmd.exe /c` on line 70, an attacker can inject arbitrary shell metacharacters to break out of the intended command.

Example attack: If `param` contains `test; rm -rf /`, the executed command becomes `sh -c "echo test; rm -rf /"`, which executes both the echo and the destructive rm command.

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

        java.util.List<String> argList = new java.util.ArrayList<String>();

        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe");
            argList.add("/c");
        } else {
            argList.add("sh");
            argList.add("-c");
        }
        argList.add("echo");
        argList.add(param);

        ProcessBuilder pb = new ProcessBuilder();

        pb.command(argList);

        try {
            // SAST FINDING: CWE-78 (OS Command Injection) - an OS command is built from request data and executed. Sink is the next statement.
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
            throw new ServletException(e);
        }
    }
}
```

## Explanation
The vulnerability exists because user input is concatenated directly into a shell command string on line 62. Although `ProcessBuilder` with a list is safer than shell string concatenation alone, the presence of `sh -c` or `cmd.exe /c` causes the shell to interpret the entire command string, including any injected metacharacters.

The fix separates the command (`echo`) from its argument (`param`) as distinct list elements:
- **Before**: `argList.add("echo " + param);` – the shell interprets this as a single string and processes any metacharacters in `param`
- **After**: `argList.add("echo"); argList.add(param);` – `echo` and the parameter are separate command arguments; `param` is passed as a literal argument to the `echo` program and is not re-interpreted by the shell

This ensures that any characters in `param` (including shell metacharacters like `;`, `|`, `&&`, backticks, etc.) are treated as literal data rather than command syntax.
