import java.io.OutputStream;
import java.net.Socket;
import javax.servlet.http.HttpServletRequest;

/**
 * Handles the "jump to folder" action in a lightweight webmail client that
 * talks to the backend IMAP server directly over a raw socket.
 */
public class ImapRawSocketFolderInjection {

    public void selectFolder(HttpServletRequest request, Socket imapSocket) throws Exception {
        // Mailbox name chosen by the signed-in user from the folder tree UI.
        String folderName = request.getParameter("folder");

        OutputStream out = imapSocket.getOutputStream();
        String command = "a1 SELECT " + folderName + "\r\n";
        // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        out.write(command.getBytes("US-ASCII"));
        out.flush();
    }
}
