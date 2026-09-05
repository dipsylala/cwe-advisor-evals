## Verdict
The code passes an untrusted caller-supplied report name directly to a batch script invocation without validation. Even though ProcessBuilder with separate arguments is generally safer than shell string concatenation, on Windows, arguments are parsed by cmd.exe when invoking batch files, allowing special characters and newlines to inject additional commands.

## Source
File: `evals/cases/78/java/ProcessBuilderBatchReentry/ReportExportService.java`, line 30

```java
ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
```

The `reportName` parameter originates from untrusted caller input (REST query parameter like `/export?report=quarterly`). A caller can supply a report name containing command injection payloads that will be interpreted by the batch script environment.

## Fix
Validate that `reportName` conforms to a strict allowlist of safe characters before passing it to the batch script:

```java
public int exportReport(String reportName) throws IOException, InterruptedException {
    // Validate reportName against a whitelist of safe characters
    if (!reportName.matches("^[a-zA-Z0-9_.-]+$")) {
        throw new IllegalArgumentException("Invalid report name: contains disallowed characters");
    }
    
    Path script = SCRIPTS_DIR.resolve("run-report.bat");
    ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
    pb.directory(SCRIPTS_DIR.toFile());
    pb.redirectErrorStream(true);

    Process process = pb.start();
    return process.waitFor();
}
```

This pattern enforces that report names contain only alphanumeric characters, underscores, dots, and hyphens—eliminating spaces, newlines, quotes, and other metacharacters that could be misinterpreted by the batch environment.

## Explanation
CWE-78 injection on Windows batch invocation requires defense even when using ProcessBuilder's argument array form. The danger stems from how Windows cmd.exe parses arguments when executing batch files: special characters like newlines, quotes, `&`, `|`, and `<`/`>` are still interpreted within individual argument values.

A whitelist validation ensures the report name is structurally constrained before it reaches the batch script. This prevents the attacker from injecting command separators, redirection operators, or other batch metacharacters that would be expanded.

The regex pattern `^[a-zA-Z0-9_.-]+$` is appropriate for typical report identifiers (such as "quarterly", "2024_q3_summary", or "report-final.txt"), while blocking all injection vectors through special characters. The exception type `IllegalArgumentException` is appropriate for invalid input that violates application constraints.
