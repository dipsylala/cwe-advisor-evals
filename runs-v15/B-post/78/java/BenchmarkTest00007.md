## Verdict

VULNERABLE

## Source

Untrusted HTTP header `BenchmarkTest00007` at line 45-46, URL-decoded at line 50.

## Fix

```java
// Line 52-62: Replace the environment variable invocation with standard execution

String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                this.getClass().getClassLoader());
String[] args = {cmd};

Runtime r = Runtime.getRuntime();

try {
    // Fixed: Execute with inherited environment, not untrusted environment variables
    Process p = r.exec(args);
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
} catch (IOException e) {
    System.out.println("Problem executing cmdi - TestCase");
    response.getWriter()
            .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
    return;
}
```

## Explanation

The vulnerability is that untrusted data from the HTTP header is passed directly as an environment variable to `Runtime.exec(args, argsEnv)`. An attacker can inject arbitrary environment variables by crafting input like `MALICIOUS=injected_value`, which would enter the child process's environment and potentially affect its behavior or enable privilege escalation depending on what the command does with environment state.

The fix removes the `argsEnv` parameter and calls `r.exec(args)` instead, which executes the command with the parent process's inherited environment. This preserves the command execution functionality while eliminating the injection vector. Untrusted data no longer reaches the process execution sink.

Per CWE-78 Java guidance: use `Runtime.exec(String[])` to pass commands as separate arguments; never pass untrusted data into any parameter of process execution APIs, including environment variables.

## Behaviour changes

- **Removed**: custom environment variable array `String[] argsEnv = {param};` at line 56
- **Changed**: `Runtime.exec(args, argsEnv)` to `Runtime.exec(args)` at line 62
- **Effect**: The subprocess now inherits the parent process's environment instead of receiving a custom single-element environment array. This is the correct behavior for this use case and eliminates the injection point.
