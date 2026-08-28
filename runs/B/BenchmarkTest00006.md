## Fix

```java
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

        // The command only echoed the supplied value back to the caller, so no process is
        // launched at all: the value is written straight to the response, HTML-encoded so it
        // cannot break out of the surrounding markup.
        response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    }
```

## Explanation

The original code built the string `"echo " + param` and handed it to `cmd.exe /c` or `sh -c` through `ProcessBuilder`, so the request header was parsed by a shell: metacharacters such as `;`, `&&`, `|`, `$(...)` or a backtick sequence would terminate the `echo` and start an attacker-chosen command with the servlet's privileges. Passing the arguments as a `List` gave no protection, because the shell itself re-parsed the final element as a whole command line. The fix removes process execution entirely rather than trying to neutralize the input: the operation being performed was simply returning the header value to the client, which the servlet can do natively with `response.getWriter()`. With no shell, no external program, and no command string, there is no injection point left, and the value is HTML-encoded on output so that eliminating the command injection does not introduce a cross-site scripting flaw in its place.
