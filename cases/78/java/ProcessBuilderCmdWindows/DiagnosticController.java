package com.example.support.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Support-desk diagnostic endpoint. Lets a helpdesk operator kick off a
 * network reachability check against a customer-reported host without
 * needing shell access to the Windows app server.
 */
@RestController
public class DiagnosticController {

    @GetMapping("/support/diagnostics/ping")
    public String runPingDiagnostic(@RequestParam("host") String host, @RequestParam("count") String count)
            throws IOException, InterruptedException {

        // Build the diagnostic command from the operator-supplied host and
        // packet count, matching what an operator would type at a prompt.
        String diagnosticCommand = "ping -n " + count + " " + host;

        // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
        Process process = new ProcessBuilder("cmd.exe", "/c", diagnosticCommand).start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            output.append("ping exited with code ").append(exitCode);
        }

        return output.toString();
    }
}
