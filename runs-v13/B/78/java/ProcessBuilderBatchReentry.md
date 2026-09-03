## Verdict

VULNERABLE. The `reportName` parameter reaches ProcessBuilder at line 30 without validation, and is passed to a Windows batch file which re-parses the command line via `cmd.exe` even though an argument array is used. An attacker can inject batch commands and options.

## Source

Line 26: `reportName` parameter (caller-supplied, untrusted) → Line 30: ProcessBuilder argument

## Fix

Apply an allowlist to accept only known report names, and set the system property to harden batch file execution:

```java
public int exportReport(String reportName) throws IOException, InterruptedException {
    // Allowlist of valid report identifiers
    Set<String> validReports = Set.of("quarterly", "monthly", "annual", "summary");
    
    if (!validReports.contains(reportName)) {
        throw new IllegalArgumentException("Invalid report name: " + reportName);
    }
    
    Path script = SCRIPTS_DIR.resolve("run-report.bat");

    // Harden batch file execution on Windows: reject ambiguous command encoding
    System.setProperty("jdk.lang.Process.allowAmbiguousCommands", "false");
    
    ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
    pb.directory(SCRIPTS_DIR.toFile());
    pb.redirectErrorStream(true);

    Process process = pb.start();
    return process.waitFor();
}
```

## Explanation

Windows batch files are interpreters themselves. When ProcessBuilder invokes a `.bat` file, the Windows kernel passes control to `cmd.exe`, which re-parses the entire command line at the system level—bypassing the argument-array protection. Even with separate arguments, special characters and redirection operators in `reportName` reach the batch interpreter as executable commands.

The fix uses two layers: **primary defence** is an allowlist that restricts `reportName` to a set of known, safe values; **secondary hardening** is the system property `jdk.lang.Process.allowAmbiguousCommands=false`, which instructs Java to reject commands it cannot unambiguously parse, raising an exception rather than falling back to error-prone encoding heuristics.

## Behaviour changes

- **New**: IllegalArgumentException thrown if `reportName` is not in the allowlist. Caller must handle this or pass only valid report identifiers.
- **Return type**: Unchanged—still returns process exit code (int) on success.
- **Exceptions**: Added IllegalArgumentException for invalid input; IOException and InterruptedException remain for process execution failures.
- **Side effect**: System property is set globally; repeated calls do not re-set it. No observable change to output or exit codes for valid inputs.
