

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Case19B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        if (data != null)
        {
            
            URI uri;
            try
            {
                uri = new URI(data);
            }
            catch (URISyntaxException exceptURISyntax)
            {
                response.getWriter().write("Invalid redirect URL");
                return;
            }
            
            // SAST FINDING: CWE-601 (URL Redirection to Untrusted Site) reported here. Sink is the next statement.
            response.sendRedirect(data);
            return;
        }

    }
}
