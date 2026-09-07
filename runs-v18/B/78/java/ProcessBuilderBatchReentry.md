## Verdict

exploitable

## Source

`reportName` parameter at line 26. Caller-supplied report identifier from REST query parameter (e.g., `/export?report=quarterly`).

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
        Path script = SCRIPTS_DIR.resolve("run-report.bat");

        // On Windows, .bat/.cmd targets cause cmd.exe re-entry even with separate arguments.
        // Set the property to reject ambiguous commands and apply stricter execution rules.
        System.setProperty("jdk.lang.Process.allowAmbiguousCommands", "false");

        ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
        pb.directory(SCRIPTS_DIR.toFile());
        pb.redirectErrorStream(true);

        Process process = pb.start();
        return process.waitFor();
    }
}
```

## Explanation

On Windows, ProcessBuilder with a `.bat`/`.cmd` file target internally invokes `cmd.exe` which re-parses the command line. Even though separate arguments prevent direct shell metacharacter injection in the calling code, `cmd.exe`'s re-parsing means an untrusted argument can still be interpreted as shell commands. For example, `reportName="quarterly & dir"` would execute both the batch file and an additional `dir` command. Setting `jdk.lang.Process.allowAmbiguousCommands=false` hardens the JVM's execution rules, making it reject ambiguous commands or apply stricter encoding rules. This is the CWE-78 Java guidance's recommended approach when the target is a batch file and cannot be easily replaced with direct invocation of the wrapped executable.

## Behaviour changes

- Added `System.setProperty("jdk.lang.Process.allowAmbiguousCommands", "false")` call before ProcessBuilder creation. This is a JVM-level hardening property that affects how the process execution engine treats potentially ambiguous commands on Windows. The property is idempotent and safe to call multiple times. Return value, exception contract, and exit code behavior remain unchanged.
