## Verdict

Confirmed. `exportReport` passes the caller-supplied `reportName` straight into a `ProcessBuilder` that launches `run-report.bat`. The `ProcessBuilder(String...)` argument-list form is documented as avoiding shell-metacharacter injection, but that guarantee does not hold here: on Windows, `ProcessBuilder`/`Runtime.exec` cannot invoke a `.bat`/`.cmd` file directly through `CreateProcess`, so the JDK transparently re-launches it as `cmd.exe /c "<script>" <args...>`. `cmd.exe` then re-tokenizes the whole command line itself, and its tokenizer treats an unescaped `"` inside an argument as toggling quote mode. `ProcessBuilder`'s Windows argument-quoting only escapes for the C-runtime `CreateProcess` convention (doubling a backslash that precedes a quote); it does not defend against `cmd.exe`'s own quote-toggle rule. A `reportName` such as `x" & calc.exe & "` closes the quoted argument early and lets `cmd.exe` parse `&`, `|`, `<`, `>`, `^`, or `%...%` as command syntax, so the export request can chain or substitute an arbitrary command that runs with the service's privileges.

## Source

`reportName` in `ReportExportService.exportReport(String reportName)`, documented as coming from a caller-controlled REST query parameter (`/export?report=...`).

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

    // Report identifiers are internal names (e.g. "quarterly",
    // "monthly-summary"), never free-form text, so a strict allowlist is
    // the right shape of check here, not an incidental hardening step.
    // This is also the primary defense, not a secondary one: on Windows,
    // launching a .bat/.cmd file through ProcessBuilder is transparently
    // rewritten by the JDK into "cmd.exe /c <script> <args>", and cmd.exe
    // re-tokenizes that whole line itself. Its quote handling lets an
    // unescaped '"' in an argument toggle out of the quoted region, so
    // ProcessBuilder's separate-argument-list form does not, by itself,
    // stop shell metacharacters (&, |, <, >, ^, %) from being interpreted
    // by cmd.exe. Rejecting anything but a known-safe identifier shape
    // closes that gap without needing to escape cmd.exe's own grammar.
    private static final Pattern REPORT_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{1,64}$");

    /**
     * Exports the named report by invoking the bundled run-report.bat
     * helper. reportName is restricted to a strict allowlist before it is
     * ever placed on the process command line, because a separate
     * ProcessBuilder argument does not by itself stop cmd.exe (which
     * Windows uses to run .bat/.cmd files) from reinterpreting shell
     * metacharacters.
     *
     * @param reportName caller-supplied report identifier, e.g. from a
     *                   REST query parameter like /export?report=quarterly
     * @return the exit code of the export process
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        if (reportName == null || !REPORT_NAME_PATTERN.matcher(reportName).matches()) {
            throw new IllegalArgumentException("Invalid report name: " + reportName);
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

The fix adds `REPORT_NAME_PATTERN` and validates `reportName` against it before it is ever used to build the process command line, rejecting the request with `IllegalArgumentException` if it doesn't match. The pattern (`^[A-Za-z0-9_-]{1,64}$`) permits only the identifier shape the doc comment already says this field holds (e.g. `quarterly`), and excludes every character `cmd.exe` treats specially — `"`, `&`, `|`, `<`, `>`, `^`, `%`, whitespace, and newlines — so there is no way for the reconstructed `cmd.exe /c run-report.bat <reportName>` line to be split into extra commands or have environment variables expanded from it.

This is deliberately the primary defense rather than a secondary check layered on top of "use `ProcessBuilder`'s argument list." The argument-list form is normally sufficient to stop shell injection, but it is not sufficient for `.bat`/`.cmd` targets on Windows: the JDK cannot pass a `.bat` file to `CreateProcess` directly, so it silently reruns the call as `cmd.exe /c <script> <args>`, and `cmd.exe` re-parses that whole line with its own quoting rules rather than trusting the process's argv. No amount of `ProcessBuilder`-side escaping closes that gap because the reinterpretation happens one layer further downstream, inside `cmd.exe` itself; only constraining what values are allowed to reach the command line does.

The identifier format here is fixed by the application (a small, known set of report names bundled with the batch script), not user-authored free text, so an allowlist is the appropriate defense in this specific case rather than a blanket recommendation — it rejects the injection payloads above while still accepting every legitimate report name the caller would ever pass. No other files needed to change: the vulnerable statement is `ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);`, and everything upstream of the validation added here is unaffected.
