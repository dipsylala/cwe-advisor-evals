package com.example.netops.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Network diagnostics endpoint used by the ops dashboard to let on-call
 * engineers check reachability of a host from the app server's network
 * segment without needing shell access to the box.
 */
public class PingDiagnosticServlet extends HttpServlet {

    private static final int PING_COUNT = 4;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        if (host == null || host.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing 'host' parameter");
            return;
        }

        StringBuilder output = new StringBuilder();
        try {
            output.append(runPing(host));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Ping interrupted");
            return;
        }

        response.setContentType("text/plain");
        response.getWriter().write(output.toString());
    }

    /**
     * Runs the platform ping utility against the requested host and returns
     * its captured stdout. The command is built as a single string because
     * the count flag and host need to appear together on the command line.
     */
    private String runPing(String host) throws IOException, InterruptedException {
        String command = "ping -c " + PING_COUNT + " " + host;
        // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
        Process process = Runtime.getRuntime().exec(command);

        StringBuilder result = new StringBuilder();
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append(System.lineSeparator());
            }
        }
        process.waitFor();
        return result.toString();
    }
}
