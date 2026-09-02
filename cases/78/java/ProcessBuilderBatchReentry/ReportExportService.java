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

        // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
        ProcessBuilder pb = new ProcessBuilder(script.toString(), reportName);
        pb.directory(SCRIPTS_DIR.toFile());
        pb.redirectErrorStream(true);

        Process process = pb.start();
        return process.waitFor();
    }
}
