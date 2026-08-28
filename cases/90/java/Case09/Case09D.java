

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case09D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case09E()).handleSink(data , request, response);
    }
}
