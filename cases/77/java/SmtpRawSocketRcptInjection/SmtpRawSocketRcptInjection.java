import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

public class SmtpRawSocketRcptInjection {

    public void sendOrderConfirmation(HttpServletRequest request) throws Exception {
        String recipientAddress = request.getParameter("customerEmail");

        Socket socket = new Socket("mail.internal.example.com", 25);
        OutputStream out = socket.getOutputStream();

        out.write("EHLO app.example.com\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("MAIL FROM:<no-reply@example.com>\r\n".getBytes(StandardCharsets.US_ASCII));

        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        out.write(("RCPT TO:<" + recipientAddress + ">\r\n").getBytes(StandardCharsets.US_ASCII));

        out.write("DATA\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write(("Subject: Order confirmation\r\n\r\nThanks for your order.\r\n.\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));

        socket.close();
    }
}
