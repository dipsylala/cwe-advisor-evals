## Verdict

Exploitable. Untrusted data from an HTTP header is passed directly as an environment variable to a child process via `Runtime.exec()`, allowing environment variable injection.

## Source

Line 46: `request.getHeader("BenchmarkTest00007")` - untrusted HTTP header value

The header value is URL-decoded at line 50 but remains untrusted user input.

## Fix

Remove the untrusted environment variables from the `Runtime.exec()` call. The `param` variable is no longer passed to the child process; instead, the child process inherits the parent's environment.

Change line 62 from:
```java
Process p = r.exec(args, argsEnv);
```

to:
```java
Process p = r.exec(args);
```

Also remove line 56 which is no longer used:
```java
String[] argsEnv = {param};
```

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
            // SAST FINDING: CWE-78 (OS Command Injection) - an OS command is built from request data and executed. Sink is the next statement.
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

The vulnerability exists because untrusted data from the HTTP header (`BenchmarkTest00007`) is passed directly into the environment variables of a child process via `Runtime.exec(String[] cmdarray, String[] envp)`. A child process that reads and uses environment variables in command construction or other sensitive operations could be exploited by an attacker controlling the header value.

The fix eliminates this injection vector by removing the untrusted environment variables and using `Runtime.exec(String[] cmdarray)` instead, which causes the child process to inherit only the parent's environment. This prevents the attacker-controlled header value from being passed into the child process's environment at all. The fix follows CWE-78 guidance: never pass untrusted data as inputs to process execution, whether as arguments, environment variables, or any other channel.

## Behaviour changes

The child process no longer receives the untrusted `param` value in its environment. The fixed code calls `Runtime.exec(args)` without the environment array parameter, which is functionally correct for the intended operation. The method signature `Runtime.exec(String[])` is a standard overload that executes the process with inherited environment variables from the parent—this is a safe default since the parent's environment is controlled, not attacker-supplied. No return value, output handling, or exception behavior has changed.
