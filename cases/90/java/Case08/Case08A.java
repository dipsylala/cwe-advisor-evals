

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case08A extends AbstractTestCaseServlet
{
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case08B()).handleSink(data , request, response);
    }
}
