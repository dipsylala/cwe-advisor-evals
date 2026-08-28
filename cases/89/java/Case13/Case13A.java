

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case13A extends AbstractTestCaseServlet
{
    private void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = "foo";

        (new Case13B()).handleSink(data , request, response );
    }
}
