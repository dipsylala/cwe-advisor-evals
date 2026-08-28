

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case05B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case05C()).handleSink(data , request, response);
    }
}
