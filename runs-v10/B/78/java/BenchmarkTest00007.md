## Verdict
exploitable

## Source
Line 46: `param = request.getHeader("BenchmarkTest00007")` - Untrusted HTTP header value.

## Fix

**Vulnerable code (lines 52-62):**
```java
String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                this.getClass().getClassLoader());
String[] args = {cmd};
String[] argsEnv = {param};  // User input placed directly into environment variables

Runtime r = Runtime.getRuntime();

try {
    // SAST FINDING: CWE-78 (OS Command Injection) - an OS command is built from request data and executed. Sink is the next statement.
    Process p = r.exec(args, argsEnv);  // argsEnv contains untrusted data
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
```

**Fixed code:**
```java
String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                this.getClass().getClassLoader());
String[] args = {cmd};

Runtime r = Runtime.getRuntime();

try {
    // Pass null for environment to inherit parent's environment, preventing injection via environment variables
    Process p = r.exec(args, null);
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
```

## Explanation
The vulnerability exists because untrusted user input from the HTTP header is passed directly into the environment variables array (`argsEnv`) of the subprocess execution. Environment variables can be exploited for OS command injection through mechanisms like LD_PRELOAD (Linux), PATH manipulation, or when the spawned subprocess uses them to construct additional commands. The fix removes the custom environment variables entirely by passing `null` instead, which causes the subprocess to inherit the parent process's environment. This eliminates the attack vector while preserving the subprocess execution behavior and the returned Process object. The application's functionality remains unchanged since the custom environment variable contained only user-controlled data with no legitimate purpose documented in the code.

## Behaviour changes
none
