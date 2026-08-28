

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case05C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case05D()).handleSink(data , request, response);
    }
}
