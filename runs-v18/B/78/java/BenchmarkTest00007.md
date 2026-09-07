## Verdict
Real vulnerability. Untrusted HTTP header value is passed as environment variable to Runtime.exec(), enabling environment variable injection attacks.

## Source
Line 45-46: `param = request.getHeader("BenchmarkTest00007")` - attacker-controlled HTTP header
Line 50: URL decoded but not validated
Line 56: Assigned to `argsEnv` array without sanitization
Line 62: Passed to `Runtime.exec(args, argsEnv)` - the sink

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
            // FIXED: Do not pass untrusted user input as environment variables.
            // Environment variables are a privileged execution context; allowing untrusted
            // data in this array enables environment variable injection attacks.
            // Use null to inherit the parent process's environment instead.
            Process p = r.exec(args, null);
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
The vulnerability was passing untrusted HTTP header data (`param`) as an environment variable to `Runtime.exec()`. Although using a string array argument list prevents shell metacharacter injection, environment variable injection remains possible because many commands and system utilities read environment variables and can be exploited through LD_PRELOAD, PATH manipulation, or other environment-based attack vectors.

The fix removes the `argsEnv` array assignment that contained `param` and passes `null` as the environment parameter instead. This tells `Runtime.exec()` to use the parent process's environment variables, preventing untrusted user input from influencing the execution environment. This maintains the original code's functionality (executing the command and printing results) while eliminating the injection vector entirely.

## Behaviour changes
The fixed code no longer accepts untrusted HTTP header values as environment variables. The executed process inherits the parent JVM's environment instead of receiving a custom environment with the attacker-controlled value. This is the correct security behavior: environment variables should be controlled by the application deployment, not by untrusted HTTP requests.
