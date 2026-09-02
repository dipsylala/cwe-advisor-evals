## Verdict

Exploitable. CWE-78 (OS Command Injection), confidence: high.

## Source

`HttpServletRequest.getHeader("BenchmarkTest00007")` (line 45-46), URL-decoded via `java.net.URLDecoder.decode(param, "UTF-8")` (line 50). The header is fully attacker-controlled and no validation or encoding is applied before it reaches the sink.

## Fix

Vulnerable code (`doPost`, lines 44-62):

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
String[] argsEnv = {param};

Runtime r = Runtime.getRuntime();

try {
    // SAST FINDING: CWE-78 (OS Command Injection) - an OS command is built from request data and executed. Sink is the next statement.
    Process p = r.exec(args, argsEnv);
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
} catch (IOException e) {
    System.out.println("Problem executing cmdi - TestCase");
    response.getWriter()
            .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
    return;
}
```

Fixed code:

```java
String cmd =
        org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(
                this.getClass().getClassLoader());
String[] args = {cmd};

Runtime r = Runtime.getRuntime();

try {
    // envp intentionally omitted: the child process inherits the JVM's own
    // environment instead of one built from unvalidated request data
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

The sink is `Runtime.exec(String[] cmdarray, String[] envp)` at line 62. The `cmdarray` argument (`args`) is built from `Utils.getInsecureOSCommandString(...)`, which is not derived from request data, so it is not the injection point here. The `envp` argument (`argsEnv`) is a single-element array containing the raw, URL-decoded header value with no validation and no `NAME=VALUE` structure enforced - the attacker supplies the entire environment the child process runs with. This lets a request set arbitrary environment entries for the spawned process (for example a crafted `PATH` or, on Linux, `LD_PRELOAD`), which can redirect the process to attacker-controlled code even though the command name itself is fixed - the exact risk the guidance's "invoke by absolute path so a writable PATH entry cannot substitute a different binary" principle addresses from the other direction: here the attacker builds the substitution vector directly instead of relying on `PATH` being writable. Removing the tainted header value from the header-reading/decoding code and env array, and calling `Runtime.exec(String[] cmdarray)` instead of the two-argument overload, closes the injection: per the JDK, `exec(cmdarray)` is equivalent to `exec(cmdarray, null, null)`, so the child process falls back to inheriting the JVM's own environment rather than one supplied over the network. The command itself continues to execute (this endpoint's purpose is running a command), so no functionality is removed - only the attacker-controlled environment channel is closed.

## Behaviour changes

- The spawned process's environment changes from a single attacker-controlled entry (`argsEnv = {param}`) to the JVM's inherited environment (the JDK's own default for the one-argument `exec(cmdarray)` overload, equivalent to `exec(cmdarray, null, null)`). This is the change that closes the weakness: any code or test that depended on the previous request-supplied environment value being visible to the child process will no longer see it.
- The header `BenchmarkTest00007` is no longer read or URL-decoded, since its only use was constructing the removed `argsEnv`. No other behaviour depends on `param`.
- `Process` return value, output handling (`Utils.printOSCommandResults`), and the `IOException` catch/response-writing path are unchanged.

Assumption: `Utils.getInsecureOSCommandString(...)` and `Utils.printOSCommandResults(...)` are fixed test-harness helpers outside the supplied file and are not part of the tainted data flow; this is consistent with the SAST finding marking line 62 (the `exec` call) as the sink and with `cmd` never being derived from `request`.
