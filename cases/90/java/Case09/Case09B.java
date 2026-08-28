

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case09B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case09C()).handleSink(data , request, response);
    }
}
