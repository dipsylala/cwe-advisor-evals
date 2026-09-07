## Verdict

Real vulnerability confirmed. The `reportName` parameter from a caller-controlled REST query parameter is passed directly to ProcessBuilder without validation. On Windows, ProcessBuilder invokes batch files through cmd.exe, which interprets shell metacharacters in arguments. An attacker can inject commands by including characters like `&`, `|`, `<`, or `>` in the reportName parameter.

## Source

Line 30 in ReportExportService.java:
```
ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
```

The `reportName` parameter originates from an untrusted source (REST query parameter per the documentation) and flows directly into the ProcessBuilder argument list without validation.

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
        // Validate reportName to reject shell metacharacters and other unsafe inputs
        if (!reportName.matches("[a-zA-Z0-9._\\-]+")) {
            throw new IllegalArgumentException("Invalid report name: contains unsafe characters");
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

The vulnerability exists because on Windows, ProcessBuilder executes batch files (.bat) through cmd.exe, which parses the command line and interprets shell metacharacters. Although ProcessBuilder with an argument array is safer than shell concatenation, cmd.exe still interprets special characters like `&` (command separator), `|` (pipe), `<` and `>` (redirection), and backticks (command substitution) in the arguments.

The fix adds input validation using a whitelist regex pattern `[a-zA-Z0-9._\-]+` that permits only alphanumeric characters, dots, underscores, and hyphens—characters that are safe in file/report names and cannot be interpreted as shell metacharacters. If the reportName contains any other character, an IllegalArgumentException is thrown.

This validation prevents command injection by ensuring user input cannot contain characters that cmd.exe would interpret as shell syntax or operators. The pattern is appropriate for report identifiers, which typically follow naming conventions that match this character set.
