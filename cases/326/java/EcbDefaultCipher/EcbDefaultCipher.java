package evalcases;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EcbDefaultCipher
{
    public void handle(HttpServletRequest request, HttpServletResponse response, SecretKey key) throws Exception
    {
        String ssn = request.getParameter("ssn");
        if (ssn == null)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // SAST FINDING: CWE-326 (Inadequate Encryption Strength) reported here. Sink is the next statement.
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(ssn.getBytes("UTF-8"));

        response.setContentType("text/plain");
        response.getWriter().write(Base64.getEncoder().encodeToString(ciphertext));
    }
}
