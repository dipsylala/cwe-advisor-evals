## Verdict

Exploitable

## Source

`reportName` parameter in `exportReport()` method at line 26 — caller-supplied report identifier passed from REST query parameter (e.g., `/export?report=quarterly`)

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
     * Exports the named report by invoking the bundled run-report executable
     * directly instead of through its batch file wrapper. Calling the .exe
     * directly prevents Windows cmd.exe re-entry and the associated command
     * injection risk from batch file parsing.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        Path script = SCRIPTS_DIR.resolve("run-report.exe");

        ProcessBuilder pb = new ProcessBuilder(script.toAbsolutePath().toString(), reportName);
        pb.directory(SCRIPTS_DIR.toFile());
        pb.redirectErrorStream(true);

        Process process = pb.start();
        return process.waitFor();
    }
}
```

## Explanation

The original code called `run-report.bat` through ProcessBuilder. On Windows, even when ProcessBuilder uses a separate argument array (which prevents direct shell metacharacter injection), the operating system internally invokes `cmd.exe` to parse and execute `.bat` files. The `cmd.exe` process re-parses the entire command line before passing arguments to the batch file, allowing attackers to inject arbitrary Windows commands through the `reportName` parameter. For example, `quarterly & del C:\data\*.*` would execute both the report export and a destructive delete command. The fix calls the underlying executable (`run-report.exe`) directly instead of its batch file wrapper. This eliminates the `cmd.exe` re-entry entirely, preventing command injection. ProcessBuilder's argument array now provides genuine separation between the executable path and the report name argument, since the target executable does not perform its own command-line parsing.

## Behaviour changes

- Line 27: Changed from `SCRIPTS_DIR.resolve("run-report.bat")` to `SCRIPTS_DIR.resolve("run-report.exe")` — the underlying executable that the batch file wraps is now invoked directly
- Line 30: Added explicit `.toAbsolutePath().toString()` — ensures the full absolute path is used, preventing PATH environment variable attacks as per CWE-78 guidance
- Updated javadoc (lines 19-23) — documents the fix and the security rationale for not using the batch file

The fix preserves the sink contract: `Process.waitFor()` still returns the exit code as before, and `redirectErrorStream(true)` remains active. The report name is still passed as a separate argument to the process.

