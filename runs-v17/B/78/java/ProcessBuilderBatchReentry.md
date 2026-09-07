## Verdict

Vulnerability confirmed. The `reportName` parameter is untrusted user input from a REST query parameter that flows directly into ProcessBuilder without validation. On Windows, invoking `.bat` files through ProcessBuilder still causes `cmd.exe` to re-parse the command line, making the argument array insufficient to prevent OS command injection via special characters.

## Source

`ReportExportService.java` line 26 parameter declaration through line 30 ProcessBuilder instantiation:
- **Input source**: `reportName` parameter - caller-supplied REST query parameter (e.g., `/export?report=quarterly`)
- **Data flow**: `reportName` → `ProcessBuilder(script.toString(), reportName)` at line 30
- **Sink**: ProcessBuilder constructor with `.bat` file invocation

## Fix

### File: ReportExportService.java

```java
package com.example.reporting;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Kicks off the legacy Windows report-export pipeline. The heavy lifting
 * (pulling data, formatting, writing the output file) lives in a bundled
 * batch script that predates this service; we just hand it the report name
 * the caller asked for.
 */
public class ReportExportService {

    private static final Path SCRIPTS_DIR = Paths.get("C:\\reporting\\scripts");

    /**
     * Exports the named report by invoking the bundled run-report.bat
     * helper. Using ProcessBuilder with a separate argument list is meant
     * to keep reportName from being interpreted as shell syntax.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        // Validate reportName to prevent OS command injection
        // On Windows, .bat files invoke cmd.exe which re-parses the command line,
        // so input validation is necessary even with ProcessBuilder argument arrays
        if (reportName == null || reportName.isEmpty()) {
            throw new IllegalArgumentException("Report name cannot be null or empty");
        }
        
        // Reject values containing shell metacharacters or starting with option flag
        // Only allow alphanumeric characters, dots, underscores, and hyphens
        if (!reportName.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]*$")) {
            throw new IllegalArgumentException("Report name contains invalid characters");
        }
        
        Path script = SCRIPTS_DIR.resolve("run-report.bat");

        ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
        pb.directory(SCRIPTS_DIR.toFile());
        pb.redirectErrorStream(true);

        Process process = pb.start();
        return process.waitFor();
    }
}
```

## Explanation

The fix adds strict input validation before passing `reportName` to ProcessBuilder. While ProcessBuilder with separate arguments prevents shell interpretation on Unix-like systems, Windows batch files are invoked through `cmd.exe`, which re-parses the command line regardless of how it was passed. The validation enforces that `reportName` matches a strict allowlist pattern: starting with an alphanumeric character and containing only alphanumeric characters, dots, underscores, and hyphens. This prevents:

1. **Shell metacharacter injection** - characters like `&`, `|`, `;`, `>`, `<`, backtick, `$()`, and others cannot be used
2. **Argument injection** - the report name cannot start with `-`, preventing it from being misinterpreted as an option flag by the batch file or any command it invokes
3. **Path traversal attempts** - absence of path separators (`..\`, `/`, etc.) prevents directory traversal

The validation uses `IllegalArgumentException` to signal invalid input, which is the standard pattern for parameter validation in Java. This is a secondary defense layer as specified in CWE-78 guidance; the primary defense (ProcessBuilder with argument arrays instead of shell strings) was already in place.

## Behaviour changes

**Exception handling**: The method now throws `IllegalArgumentException` if `reportName` is null, empty, or contains invalid characters. Callers must handle this exception or ensure they only pass valid report names. This is a breaking change for callers that were passing arbitrary strings, but those callers were exposing the vulnerability.

**Valid report names**: Only report names matching the pattern `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` are accepted. Examples of valid names: `quarterly`, `Q1-2024`, `report_v2.1`, `monthly.backup`. Invalid names that are now rejected include those containing spaces, special shell characters, or starting with hyphens.

**Exit codes and output**: The method behavior is otherwise unchanged - it still returns the process exit code and redirects error stream to standard output exactly as before.
