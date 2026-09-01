## Verdict

Exploitable. The untrusted HTTP header value is concatenated into a command string and executed via ProcessBuilder with shell interpretation, allowing arbitrary command execution.

## Source

Line 45-46: `request.getHeader("BenchmarkTest00006")` provides untrusted user input. Line 50 URL-decodes it but does not validate. Line 62 concatenates this into a command string without any sanitization or allowlist.

## Fix

**Vulnerable code (lines 52-76):**
```java
java.util.List<String> argList = new java.util.ArrayList<String>();

String osName = System.getProperty("os.name");
if (osName.indexOf("Windows") != -1) {
    argList.add("cmd.exe");
    argList.add("/c");
} else {
    argList.add("sh");
    argList.add("-c");
}
argList.add("echo " + param);

ProcessBuilder pb = new ProcessBuilder();

pb.command(argList);

try {
    // SAST FINDING: CWE-78 (OS Command Injection) - an OS command is built from request data and executed. Sink is the next statement.
    Process p = pb.start();
    org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
} catch (IOException e) {
    System.out.println(
            "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
    throw new ServletException(e);
}
```

**Fixed code:**
```java
try {
    response.getWriter().print(param);
} catch (IOException e) {
    System.out.println(
            "Problem executing cmdi - java.lang.ProcessBuilder(java.util.List) Test Case");
    throw new ServletException(e);
}
```

## Explanation

The vulnerability occurs because the untrusted parameter is concatenated into a shell command string (`"echo " + param`) and executed via ProcessBuilder with shell invocation (`sh -c` or `cmd.exe /c`). This allows the shell to interpret metacharacters in the parameter as command separators or operators. The remediation eliminates process execution entirely, replacing it with direct response output using Java's standard ServletResponse.getWriter(). Since the purpose is incidental (outputting a parameter to the user), not the feature itself, using native Java APIs to write output is the appropriate fix. This eliminates the command injection vector completely while preserving the original output behavior.

## Behaviour changes

The fixed code removes the ProcessBuilder subprocess creation and platform-specific shell logic, replacing it with direct response output. The parameter is written to the response writer instead of being echoed through a shell process. This preserves the original behavior (the parameter is output to the response in both cases) while eliminating the command injection vulnerability. The IOException handling remains unchanged and still propagates errors to the servlet container as before.
