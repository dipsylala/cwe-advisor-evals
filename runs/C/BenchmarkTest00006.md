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

        // The command was only ever "echo <param>", i.e. write a value back to the caller.
        // That needs no OS process at all, so the shell invocation and the ProcessBuilder
        // are removed outright rather than being made safer. The value is HTML-encoded on
        // the way out because it is now rendered directly into a text/html response.
        response.getWriter().println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    }
```

## Explanation

The original method placed an attacker-controlled request header into a command string (`"echo " + param`) and handed that string to `cmd.exe /c` or `sh -c` through `ProcessBuilder.start()`, so shell metacharacters such as `;`, `|`, `&&`, or `$(...)` in the header would be parsed by the shell and executed as additional commands on the host. Passing the arguments as a `List` gave no protection here, because the list still names a shell interpreter whose final element is a command line the shell re-parses. The fix removes the process execution entirely: the only work the command performed was echoing a value back to the client, and that is done natively by writing to the servlet response, so there is no longer any shell, any command string, and therefore no injection point at all. The value is HTML-encoded as it is written so that eliminating the command injection does not introduce a cross-site scripting issue in the `text/html` response.
