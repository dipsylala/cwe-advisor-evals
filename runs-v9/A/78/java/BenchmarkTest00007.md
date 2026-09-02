## Verdict

Confirmed. CWE-78 OS Command Injection.

## Source

`request.getHeader("BenchmarkTest00007")` (line 45-46), URL-decoded at line 50 into `param`, then placed into the `argsEnv` array at line 56 and passed straight to `Runtime.exec(String[] cmdarray, String[] envp)` at line 62 with no validation, allowlisting, or encoding in between.

## Fix

```java
String param = "";
if (request.getHeader("BenchmarkTest00007") != null) {
    param = request.getHeader("BenchmarkTest00007");
}

// URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
param = java.net.URLDecoder.decode(param, "UTF-8");

// Reject anything that isn't a safe, single-token environment-variable value before
// it is allowed anywhere near process creation. No control characters, no shell
// metacharacters, no embedded '=' (which would let the value redefine which
// variable is being set rather than just its content).
if (!param.matches("[A-Za-z0-9_.-]{0,256}")) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    response.getWriter().println("Invalid input.");
    return;
}

String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                this.getClass().getClassLoader());
String[] args = {cmd};
String[] argsEnv = {"BENCHMARK_VALUE=" + param};

Runtime r = Runtime.getRuntime();

try {
    Process p = r.exec(args, argsEnv);
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
} catch (IOException e) {
    System.out.println("Problem executing cmdi - TestCase");
    response.getWriter()
            .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
    return;
}
```

## Explanation

`argsEnv` is passed as the `envp` argument of `Runtime.exec(String[] cmdarray, String[] envp)`, which the JVM expects to be a list of `NAME=VALUE` environment-variable definitions for the spawned process. The original code puts the raw, attacker-controlled, URL-decoded header value directly into that array with no `NAME=` prefix and no restriction on content. That lets a caller supply a value containing `=` to redefine which environment variable is actually being set (for example smuggling in `LD_PRELOAD=...` or `PATH=...` instead of the intended variable), or supply control characters/other unexpected content that downstream tooling invoked by `cmd` may read and act on - an environment-variable injection that is a variant of CWE-78 exec-argument injection rather than classic shell metacharacter injection, since `cmd` itself carries no shell.

The fix closes this by (1) allowlisting `param` to a short, fixed character set (`A-Za-z0-9_.-`) before it is used anywhere, rejecting the request outright if it doesn't match, and (2) constructing the environment entry as a fixed `"BENCHMARK_VALUE=" + param` string so the attacker only ever controls the value half of one specific, already-named variable and can never inject a second variable or override an unrelated one via an embedded `=`. This preserves the program's existing behavior (passing the header value through to the child process) while eliminating the attacker's ability to control which environment variable is set or to smuggle unexpected characters into it. `args` (the command itself) is unchanged since it is produced by `Utils.getInsecureOSCommandString`, not by request data.
