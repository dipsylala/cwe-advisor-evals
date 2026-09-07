## Verdict
exploitable

## Source
`request.getHeader("BenchmarkTest00007")` at line 45, URL-decoded at line 50

## Fix

**Vulnerable code (line 62):**
```java
String[] args = {cmd};
String[] argsEnv = {param};  // param is untrusted user input

Runtime r = Runtime.getRuntime();
Process p = r.exec(args, argsEnv);  // CWE-78: param passed to environment
```

**Fixed code:**
```java
String[] args = {cmd};

Runtime r = Runtime.getRuntime();
Process p = r.exec(args);  // Removed untrusted environment variable injection
```

## Explanation

The vulnerability exists because untrusted user input from the HTTP header is passed directly into the environment variable array of `Runtime.exec()`. The second parameter to `Runtime.exec(String[] cmdarray, String[] envp)` is an array of environment variables in `"NAME=VALUE"` format. By passing `{param}` without validation or proper formatting, the unsanitized user input becomes part of the process environment, allowing an attacker to manipulate environment variables used by the executed command. This can enable command injection through environment-based attack vectors (e.g., `PATH` manipulation, `LD_PRELOAD`, `IFS` modification). Removing the environment variable parameter entirely and using only the default inherited environment closes this injection path.

## Behaviour changes

The fixed code omits the second parameter to `Runtime.exec()`, which causes the spawned process to inherit the current process's environment variables instead of using the explicitly provided array. This is the safer default behavior. The original code attempted to pass the HTTP header value as an environment variable without validation or proper `NAME=VALUE` formatting, which was exploitable. The fix does not preserve the original behavior of passing custom environment variables because that behavior was the source of the vulnerability and was not being used correctly (the param was not in `NAME=VALUE` format).
