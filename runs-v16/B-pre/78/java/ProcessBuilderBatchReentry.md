## Verdict

Exploitable. The `reportName` parameter flows from an untrusted source (REST query parameter) directly into a `ProcessBuilder` call that invokes a Windows batch file. On Windows, `.bat`/`.cmd` files re-parse their command line through `cmd.exe`, allowing attackers to inject shell metacharacters and commands even when using `ProcessBuilder`'s argument array form. Additionally, without input validation, a value starting with `-` could be interpreted as an option flag by the batch script or its spawned process, enabling argument injection (CWE-88).

## Source

The `reportName` parameter in the `exportReport(String reportName)` method signature. This is documented as "caller-supplied report identifier, e.g. from a REST query parameter like /export?report=quarterly". An attacker can supply arbitrary values for this parameter.

## Fix

**Vulnerable code (line 30):**
```java
public int exportReport(String reportName) throws IOException, InterruptedException {
    Path script = SCRIPTS_DIR.resolve("run-report.bat");

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
    pb.directory(SCRIPTS_DIR.toFile());
    pb.redirectErrorStream(true);

    Process process = pb.start();
    return process.waitFor();
}
```

**Fixed code:**
```java
public int exportReport(String reportName) throws IOException, InterruptedException {
    // Validate report name against a strict allowlist pattern to prevent command injection
    // Reject values containing special characters or starting with dash (option injection)
    if (!reportName.matches("^[a-zA-Z0-9][a-zA-Z0-9_-]*$")) {
        throw new IllegalArgumentException("Invalid report name: " + reportName);
    }

    Path script = SCRIPTS_DIR.resolve("run-report.bat");
    ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
    pb.directory(SCRIPTS_DIR.toFile());
    pb.redirectErrorStream(true);

    Process process = pb.start();
    return process.waitFor();
}
```

## Explanation

The fix adds input validation that constrains `reportName` to a safe character set before it reaches the `ProcessBuilder` sink. The pattern `^[a-zA-Z0-9][a-zA-Z0-9_-]*$` ensures the value starts with an alphanumeric character and contains only alphanumeric characters, underscores, and hyphens. This prevents shell command injection by rejecting values containing metacharacters (`;`, `|`, `&`, `` ` ``, `$`, etc.) and prevents option injection (CWE-88) by rejecting values starting with `-`.

On Windows, `.bat`/`.cmd` files invoke `cmd.exe` to parse their command line, so `ProcessBuilder`'s argument array alone is insufficient to prevent injection. Strict input validation closes this gap by ensuring the attacker-controlled value cannot be interpreted as a command or option by the shell. The canonical validated value (the reportName after the allowlist check passes) is then used in the ProcessBuilder call.

## Behaviour changes

- **Added input validation with exception on invalid input**: The method now throws `IllegalArgumentException` if `reportName` does not match the allowlist pattern. Previously, any reportName would be accepted and passed to the batch script, where it could be interpreted as a command. This is a necessary defensive change; report names that contained special characters or started with `-` will now be rejected. Callers should handle `IllegalArgumentException` as an invalid user input error (typically a 400 Bad Request response in a REST endpoint).

- **Stricter report name format**: The reportName must now conform to the pattern `[a-zA-Z0-9][a-zA-Z0-9_-]*`. Any existing report names using other characters (spaces, dots, quotes, parentheses, etc.) will no longer be accepted. This is appropriate for report identifiers, which typically use alphanumeric names with underscores or hyphens (e.g., "quarterly_2024", "annual-report"). If the application needs to support a broader character set, the pattern should be defined based on the specific report naming requirements and validated against that definition instead.
