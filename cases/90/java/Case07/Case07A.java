

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case07A extends AbstractTestCaseServlet
{
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = request.getParameter("name");

        (new Case07B()).handleSink(data , request, response );
    }
}
