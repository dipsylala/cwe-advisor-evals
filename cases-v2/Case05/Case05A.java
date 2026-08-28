

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case05A extends AbstractTestCaseServlet
{
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case05B()).handleSink(data , request, response);
    }
}
