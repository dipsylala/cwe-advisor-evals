## Fix

```java
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

        // Request data must never define an environment entry: a "NAME=value" string chosen by
        // the caller can set PATH, IFS, LD_PRELOAD or BASH_ENV and take over the child process.
        // Accept only an allowlisted value, and bind it to a fixed variable name we control.
        if (!param.matches("[A-Za-z0-9_.-]{0,64}")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Invalid input.");
            return;
        }

        // Resolve the configured program to an absolute path so a writable PATH entry cannot
        // substitute a different binary, and launch it directly with no shell.
        java.nio.file.Path command =
                java.nio.file.Paths.get(
                                org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                                                this.getClass().getClassLoader())
                                        .trim())
                        .toAbsolutePath()
                        .normalize();

        ProcessBuilder pb = new ProcessBuilder(command.toString());
        pb.environment().put("BENCHMARK_INPUT", param);

        try {
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
```

## Explanation

The tainted header reached the process not as an argument but as the whole environment block of `Runtime.exec(String[], String[])`, where each element is a raw `NAME=value` pair: the caller therefore chose both the variable names and their values, and could set `PATH`, `IFS`, `LD_PRELOAD`, or `BASH_ENV` to make the launched program resolve or execute code of the attacker's choosing, which is command injection by way of the child's execution context rather than its command line. The fix stops request data from defining environment entries at all: the value is checked against a strict allowlist of characters and length before use, and is then bound to a single fixed variable name via `ProcessBuilder.environment()`, so the caller can influence one value the program expects and nothing about how it is resolved or interpreted. The program itself is resolved to an absolute, normalized path and started with no shell wrapper, which removes both the `PATH`-substitution avenue and any metacharacter parsing; on Windows this should be paired with running `jdk.lang.Process.allowAmbiguousCommands=false` and pointing at the real executable rather than a `.bat`/`.cmd` wrapper, since a batch target re-enters `cmd.exe` and has its command line reparsed regardless of how the caller supplied the arguments.
