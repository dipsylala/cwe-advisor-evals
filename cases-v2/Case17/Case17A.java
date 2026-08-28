

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case17A extends AbstractTestCaseServlet
{
    private void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = "foo";

        (new Case17B()).handleSink(data , request, response );
    }
}
