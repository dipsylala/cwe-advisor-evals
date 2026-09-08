## Verdict

Exploitable. `exportReport(String reportName)` in `ReportExportService.java` passes a caller-supplied report identifier (documented as coming straight from a REST query parameter, e.g. `/export?report=quarterly`) as an argument to `ProcessBuilder`, which spawns `run-report.bat`. Confidence: high.

## Source

`reportName`, the parameter of `ReportExportService.exportReport(String reportName)` - caller-supplied, sourced from an HTTP query parameter per the method's own Javadoc. It reaches the sink with no validation or sanitization in between; `script` (the resolved path to `run-report.bat`) is not attacker-controlled.

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

    // Report identifiers are an application-owned format: short alphanumeric
    // tokens (plus '-'/'_'), never free text. This rejects anything that
    // could be read as a cmd.exe metacharacter (&, |, <, >, ^, %, quotes,
    // whitespace) when run-report.bat is re-parsed by cmd.exe on Windows.
    private static final Pattern VALID_REPORT_NAME = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    /**
     * Exports the named report by invoking the bundled run-report.bat
     * helper. Using ProcessBuilder with a separate argument list does not,
     * by itself, keep reportName from being interpreted as shell syntax:
     * on Windows a .bat target has no native argv, so the JVM re-enters
     * cmd.exe to run it, and cmd.exe re-parses the command line. The
     * report name is therefore validated against an allowlisted format
     * before it is ever placed on that command line.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        if (reportName == null || !VALID_REPORT_NAME.matcher(reportName).matches()) {
            throw new IllegalArgumentException("Invalid report name");
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

`ProcessBuilder`'s argument-array form only avoids injection when the target program is a native executable with its own argv; `run-report.bat` is a batch file, which Windows cannot execute directly via `CreateProcess`, so the JVM re-enters `cmd.exe` to run it and `cmd.exe` re-parses the assembled command line, including `reportName`. An unvalidated value can therefore still inject `cmd.exe` metacharacters (`&`, `|`, `<`, `>`, `^`, `%`, quotes) despite the array form, spawning arbitrary commands. The fix adds a `Matcher.matches()` check (full-string match, not `find()`, so a trailing newline or partial match can't slip through) against a strict allowlisted format for report identifiers - alphanumeric plus `-`/`_`, 1-64 characters - before the value is ever placed on the command line passed to `ProcessBuilder`. This is the "value has a format the application owns" case: a report id is a short application-level token, not free text, so constraining it to that shape rejects every character `cmd.exe` treats specially without excluding any realistic report name. The batch script's internals (and what executable it ultimately wraps) are outside the provided file, so the guidance's stronger recommendation - invoking the wrapped executable directly and bypassing `cmd.exe` re-entry entirely - could not be applied here; that should be revisited once `run-report.bat`'s contents are available. Setting the JVM-wide `-Djdk.lang.Process.allowAmbiguousCommands=false` launch flag is a further hardening step worth adding at deployment time, but it is not a substitute for validating the argument, since the batch re-parse remains regardless of that flag.

## Behaviour changes

- Added: rejects any `reportName` that is `null` or does not match `[A-Za-z0-9_-]{1,64}` by throwing `IllegalArgumentException("Invalid report name")` before the process is spawned. Previously any string, including one containing spaces, shell metacharacters, or path separators, was passed through unchecked. This is a deliberate narrowing required to close the injection; any legitimate caller using report identifiers of this shape (e.g. `quarterly`, `q3-2026`) is unaffected. Assumption: the actual catalog of report names used in production is not visible in the provided file; if any legitimate report id uses characters outside this set (e.g. a space or a dot), the allowlist pattern will need to be widened to match the real catalog while still excluding shell metacharacters.
- No change to `ProcessBuilder` construction, working directory, stream redirection, process invocation, or return value - the exit code contract (`process.waitFor()`) is preserved exactly.

Verification: compiled with `javac` (JDK 26) against a copy of the file in an isolated scratch directory - compiled cleanly with no errors or warnings.
