

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case15A extends AbstractTestCaseServlet
{
    private void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = "foo";

        (new Case15B()).handleSink(data , request, response );
    }
}
