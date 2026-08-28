

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case06A extends AbstractTestCaseServlet
{
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case06B()).handleSink(data , request, response);
    }
}
