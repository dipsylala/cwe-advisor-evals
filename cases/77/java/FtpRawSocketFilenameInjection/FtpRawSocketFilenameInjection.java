import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Downloads a report file from the archive FTP server on behalf of a
 * report-export request.
 */
public class FtpRawSocketFilenameInjection {

    public void fetchReportFile(String requestedFileName) throws IOException {
        // requestedFileName comes straight from the export request payload
        try (Socket ftpSocket = new Socket("ftp.internal.example.com", 21)) {
            OutputStream out = ftpSocket.getOutputStream();
            out.write("USER reportsvc\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write("PASS ${FTP_REPORTSVC_PASS}\r\n".getBytes(StandardCharsets.US_ASCII));

            String command = "RETR " + requestedFileName + "\r\n";
            // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
            out.write(command.getBytes(StandardCharsets.US_ASCII));
            out.flush();
        }
    }
}
