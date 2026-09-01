## Verdict

Exploitable. Untrusted HTTP header input is passed without validation as an environment variable to a child process via Runtime.exec().

## Source

`request.getHeader("BenchmarkTest00007")` (line 45-46), URL-decoded (line 50), assigned to `param`

## Fix

**Vulnerable code:**
```java
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
String[] argsEnv = {param};  // VULNERABLE: untrusted param as environment variable

Runtime r = Runtime.getRuntime();

try {
    Process p = r.exec(args, argsEnv);  // SINK: param reaches child process environment
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
```

**Fixed code:**
```java
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
    Process p = r.exec(args);  // FIXED: pass no environment variables; inherit parent's trusted environment
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
```

## Explanation

The vulnerability occurs because untrusted input from an HTTP header is passed as an environment variable to a child process. Even though the input is not directly concatenated into a command string, environment variables can be exploited if the executed command interprets them unsafely. The fix removes the untrusted environment variable by calling `Runtime.exec(args)` instead of `Runtime.exec(args, argsEnv)`. This causes the child process to inherit the parent's environment (which is trusted) rather than receiving attacker-controlled environment variables. The `param` variable is no longer used, and the unused `argsEnv` array creation has been removed.

## Behaviour changes

- **Removed**: `String[] argsEnv = {param};` declaration and population
- **Changed**: `r.exec(args, argsEnv)` → `r.exec(args)` - child process now inherits parent environment instead of receiving attacker-controlled environment variables
- **Impact on process environment**: The executed command now runs with the parent JVM's environment rather than a modified environment containing untrusted header data. This is the correct and safer behavior for process execution.
