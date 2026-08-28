## Fix
```java
    /** Self-contained tokens only; no shell metacharacter can match this pattern. */
    private static final java.util.regex.Pattern SAFE_ARGUMENT =
            java.util.regex.Pattern.compile("\\A[A-Za-z0-9._-]{1,64}\\z");

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

        // Validate after decoding, so the check inspects exactly the value the OS will receive.
        if (!SAFE_ARGUMENT.matcher(param).matches()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("Invalid argument.");
            return;
        }

        // Program name and fixed arguments are literals. The request value is passed as its
        // own argv element and is never concatenated into a command string.
        java.util.List<String> argList = new java.util.ArrayList<String>();

        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe");
            argList.add("/c");
            argList.add("echo");
        } else {
            argList.add("/bin/echo");
        }
        argList.add(param);

        ProcessBuilder pb = new ProcessBuilder(argList);

        try {
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println(
                    "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
            throw new ServletException(e);
        }
    }
```

## Explanation
The original code built a single shell command string, `"echo " + param`, and handed it to `sh -c` (or `cmd.exe /c`), so the shell parsed the request header as command syntax and any `;`, `|`, `&&`, backtick, or `$(...)` in it ran as a separate command. The fix removes the shell from the execution path: the process is now `/bin/echo` invoked directly (on Windows, `cmd.exe /c echo` with the value kept as a distinct element rather than spliced into the command line), and the header value is added to the argument list as its own element, so the operating system passes it to the program as literal argv data that is never re-parsed. A decode-then-validate allowlist is applied as defence in depth, rejecting anything outside `[A-Za-z0-9._-]` before the value reaches the process layer; it runs after `URLDecoder.decode` so encoded metacharacters cannot slip past the check and be decoded later. Behaviour for legitimate input is unchanged, while injected command fragments are either rejected by validation or, if the allowlist were widened, treated as a harmless single argument.
