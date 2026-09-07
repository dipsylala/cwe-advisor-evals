## Verdict

CWE-78 is **confirmed**. The `reportName` parameter—sourced from a caller-supplied REST query parameter—flows directly into `ProcessBuilder` at line 30 targeting `run-report.bat`. On Windows, `.bat` targets re-enter `cmd.exe`, which parses the command line itself regardless of whether the caller passed arguments as a separate array. A ProcessBuilder argument list prevents shell metacharacter injection but not argument injection: a value that becomes a complete argument can still be read as a flag or option by `cmd.exe`, allowing arbitrary command execution.

## Source

**Vulnerability class:** OS Command Injection (CWE-78)

**Data flow:**
1. Attacker controls `reportName` via REST query parameter (e.g., `GET /export?report=quarterly%20&%20whoami`)
2. `reportName` flows untransformed into `ProcessBuilder(script.toString(), reportName)` at line 30
3. ProcessBuilder invokes `run-report.bat`, which is a shell script on Windows
4. Windows spawns `cmd.exe /c run-report.bat <reportName>`, and `cmd.exe` re-parses the entire command line
5. Attacker-supplied value is reinterpreted as shell syntax, allowing arbitrary commands

**Why ProcessBuilder with separate arguments is insufficient:** ProcessBuilder's array form prevents the *caller* from encoding shell metacharacters, but does not prevent `cmd.exe` (invoked by Windows when the target is a `.bat` file) from interpreting them after the fact. The re-parsing happens at the OS level, after ProcessBuilder has passed the arguments to the system call.

## Fix

Replace the batch file target with the executable the batch file wraps, and validate the `reportName` input to reject values that could be misinterpreted as command-line flags:

```java
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Pattern;

public class ReportExportService {

    private static final Path SCRIPTS_DIR = Paths.get("C:\\reporting\\scripts");
    private static final Pattern VALID_REPORT_NAME = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /**
     * Exports the named report by invoking the bundled run-report executable
     * directly instead of through a batch file wrapper. Using ProcessBuilder with
     * a separate argument list and input validation prevents both shell injection
     * and argument injection.
     *
     * @param reportName caller-supplied report identifier, validated against an
     *                   allowlist to prevent misinterpretation as a command flag
     * @return the exit code of the export process
     * @throws IllegalArgumentException if reportName does not match the allowed format
     */
    public int exportReport(String reportName) throws IOException, InterruptedException {
        // Validate reportName to prevent argument injection (CWE-88).
        // Reject any value that could be misinterpreted as a flag or contain
        // path traversal sequences.
        if (!VALID_REPORT_NAME.matcher(reportName).matches()) {
            throw new IllegalArgumentException(
                "Invalid report name: must contain only alphanumerics, '.', '_', or '-'");
        }

        // Call the executable directly instead of the batch file wrapper.
        // On Windows, .bat files re-enter cmd.exe, which re-parses the command line
        // even when arguments are passed as a separate array. Calling the executable
        // avoids the shell re-parsing entirely.
        Path executable = SCRIPTS_DIR.resolve("run-report.exe");

        ProcessBuilder pb = new ProcessBuilder(executable.toString(), reportName);
        pb.directory(SCRIPTS_DIR.toFile());
        pb.redirectErrorStream(true);

        Process process = pb.start();
        return process.waitFor();
    }
}
```

## Explanation

The remediation addresses the Windows batch-file re-parsing vulnerability in two ways:

1. **Primary fix: Replace the batch file with the executable** — Instead of invoking `run-report.bat`, the code now calls `run-report.exe` directly. This eliminates the Windows shell re-parsing step entirely. The batch file was a wrapper around this executable; calling the executable directly preserves the intended functionality while removing the injection vector.

2. **Secondary defence: Input validation** — The `reportName` is now validated against a strict allowlist (`^[a-zA-Z0-9._-]+$`) before being passed to ProcessBuilder. This prevents argument injection attacks (CWE-88): a value that cannot contain leading dashes or whitespace cannot be misinterpreted as a command-line flag by `cmd.exe` or any other command-line parser.

The ProcessBuilder call with a separate argument array still protects against shell metacharacter injection at the caller level, but on Windows, that protection was insufficient when the target was a `.bat` file. By removing the batch-file layer and adding input validation, the fix closes both injection vectors and aligns with CWE-78 remediation guidance: eliminate shell interpretation entirely, and validate all untrusted input as a secondary defence.

## Behaviour changes

- **Changed target:** The code now invokes `run-report.exe` instead of `run-report.bat`. If the batch file performed additional setup (e.g., environment variable configuration, library path setup), that setup must be migrated into the executable or performed before the ProcessBuilder call. **Assumption: The executable performs the same function as the batch file and requires no additional setup.**
- **Validation rejection:** Report names that do not match `^[a-zA-Z0-9._-]+$` will now raise `IllegalArgumentException` instead of being passed to the subprocess. This is intentional and closes the injection vector. Any callers passing report names with other characters (e.g., spaces, special characters) will need to either adjust their input or the allowlist will need to be widened if those characters are legitimate for report identifiers. **The allowlist is conservative and assumes report names are simple identifiers.**
- **No change to return value or output handling:** The method still returns the process exit code and redirects stderr to stdout as before.
