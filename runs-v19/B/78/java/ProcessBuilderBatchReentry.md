## Verdict
Exploitable

## Source
The `reportName` parameter received from the HTTP query string (e.g., `/export?report=quarterly`), passed to the `exportReport()` method as an untrusted caller-supplied value.

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
     * helper. The report name is validated to contain only safe characters,
     * preventing command injection through batch file parameter expansion.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     * @throws IllegalArgumentException if reportName contains invalid characters
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        // Validate report name contains only safe characters to prevent injection
        // through cmd.exe parameter expansion when the batch file is invoked
        if (!reportName.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException(
                "Invalid report name: must contain only alphanumeric characters, underscores, and hyphens"
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
On Windows, invoking a `.bat` file does not execute it directly; the operating system invokes `cmd.exe` with the batch file as an argument, and `cmd.exe` re-parses the entire command line. Although `ProcessBuilder` with a separate argument list prevents shell metacharacter injection in most contexts, it does not protect against injection through the Windows batch file re-parsing: special characters in `reportName` such as `&`, `|`, `;`, or `$` are interpreted as shell syntax by `cmd.exe`. The fix validates the `reportName` parameter against a strict allowlist pattern that permits only alphanumeric characters, underscores, and hyphens—a reasonable constraint for a report identifier that the application defines. This validation prevents all forms of command injection through the batch file parameter expansion and is the primary defence where the batch file execution is kept (rather than replaced with a Java library alternative). Invalid report names are rejected with an exception that the caller can catch and convert to an appropriate HTTP error response.

## Behaviour changes
The method now throws `IllegalArgumentException` if `reportName` contains characters outside the safe set. This is a breaking change for callers that pass invalid report names, but those callers were already passing unsanitized user input to a command-line sink, so rejecting them is correct. The method's successful-case return value and exception contract (`IOException`, `InterruptedException`) remain unchanged. The underlying process exit code semantics are unaffected; a valid report name still produces the same exit code as before.
