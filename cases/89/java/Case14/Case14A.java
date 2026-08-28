

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case14A extends AbstractTestCaseServlet
{
    private void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case14B()).handleSink(data , request, response );
    }
}
