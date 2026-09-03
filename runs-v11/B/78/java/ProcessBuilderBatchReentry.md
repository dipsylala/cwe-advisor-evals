## Verdict

Confirmed. OS Command Injection via untrusted `reportName` parameter to Windows batch file execution.

## Source

Line 30 passes `reportName` directly to `ProcessBuilder` targeting a `.bat` script. Although `ProcessBuilder` uses an argument array (which prevents shell metacharacter injection), on Windows a `.bat` target re-enters `cmd.exe`, which re-parses the command line. The parameter becomes injectable: a caller can supply `"quarterly & del C:\important"` and the batch file will execute both the intended command and the injected one.

## Fix

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
    private static final Pattern VALID_REPORT_NAME = Pattern.compile("^[a-zA-Z0-9_-]+$");

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
        // Validate report name against allowlist: only alphanumeric, underscore, and hyphen
        if (!VALID_REPORT_NAME.matcher(reportName).matches()) {
            throw new IllegalArgumentException(
                "Invalid report name. Must contain only letters, numbers, underscores, and hyphens."
            );
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

The vulnerability exists because Windows batch files (`.bat`, `.cmd`) trigger re-invocation of `cmd.exe` at the system level, bypassing the argument-array protection that `ProcessBuilder` provides. Even with an argument array, `cmd.exe` re-parses the entire command line, allowing an attacker to inject additional commands via shell metacharacters (`&`, `|`, `||`, `&&`, `;`, `(`, `)`) embedded in an argument.

The fix adds a strict allowlist validation that restricts `reportName` to safe characters: `[a-zA-Z0-9_-]`. This prevents an attacker from including shell metacharacters that `cmd.exe` would interpret. The pattern rejects any input containing spaces, quotes, special characters, or path traversal sequences.

Input validation is the secondary defence layer here (per CWE-78 guidance). The primary defence would be to invoke the executable that `run-report.bat` wraps directly instead of the batch file, but that requires knowing the internal structure of the batch script and is a larger refactoring.

## Behaviour changes

**Before fix:** Accepts any string as `reportName`, including values like `"quarterly & cmd /c del C:\data"`, which would execute injected commands through the batch file re-entry into `cmd.exe`.

**After fix:** Rejects any `reportName` containing characters outside `[a-zA-Z0-9_-]`. Throws `IllegalArgumentException` with a clear message if validation fails. Legitimate report names like `"quarterly"`, `"monthly-summary"`, and `"q1_2024"` are accepted.

**Functional equivalence:** The fixed code returns the same exit code as the original for valid inputs, and properly rejects dangerous inputs before invocation rather than allowing injection.
