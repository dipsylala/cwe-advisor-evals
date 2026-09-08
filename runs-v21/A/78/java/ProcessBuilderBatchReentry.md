## Verdict

CONFIRMED. The reportName parameter, sourced from caller input (REST query parameter), flows directly into ProcessBuilder arguments to a Windows batch script. On Windows, batch file execution requires cmd.exe invocation, where the arguments are subject to shell metacharacter interpretation. Special characters like %, !, ^, &, |, <, >, and parentheses can be interpreted as batch commands or operators, enabling OS command injection.

## Source

`reportName` parameter in `exportReport()` method, originating from caller input (documented as REST query parameter in JavaDoc).

## Fix

### File: ReportExportService.java

```java
package com.example.reporting;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

/**
 * Kicks off the legacy Windows report-export pipeline. The heavy lifting
 * (pulling data, formatting, writing the output file) lives in a bundled
 * batch script that predates this service; we just hand it the report name
 * the caller asked for.
 */
public class ReportExportService {

    private static final Path SCRIPTS_DIR = Paths.get("C:\\reporting\\scripts");
    private static final Pattern SAFE_REPORT_NAME = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /**
     * Exports the named report by invoking the bundled run-report.bat
     * helper. Using ProcessBuilder with a separate argument list is meant
     * to keep reportName from being interpreted as shell syntax.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     * @throws IllegalArgumentException if reportName contains invalid characters
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        if (reportName == null || !SAFE_REPORT_NAME.matcher(reportName).matches()) {
            throw new IllegalArgumentException("Invalid report name: must contain only alphanumerics, dots, hyphens, and underscores");
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

The fix adds input validation before passing `reportName` to ProcessBuilder:

1. **Strict allowlist pattern**: `^[a-zA-Z0-9._-]+$` permits only alphanumerics, dots, hyphens, and underscores—characters safe in identifiers and filenames and incapable of batch metacharacter sequences.

2. **Null check**: Prevents null pointer exception and catches empty/invalid inputs.

3. **Early rejection**: Throws `IllegalArgumentException` for invalid names, preventing execution with unsafe values.

4. **Preserves legitimacy**: Report names like `quarterly`, `2025_Q1`, `report.backup`, and `monthly-summary` pass validation; injection attempts like `report&del /s /q C:\` or `report%OS%` are rejected.

This ensures that ProcessBuilder receives only structurally constrained values incapable of being interpreted as batch commands, eliminating the OS command injection vector while maintaining the application's intended functionality.

