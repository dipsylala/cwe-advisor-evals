

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case09A extends AbstractTestCaseServlet
{
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case09B()).handleSink(data , request, response);
    }
}
