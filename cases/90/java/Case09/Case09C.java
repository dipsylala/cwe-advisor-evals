

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case09C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case09D()).handleSink(data , request, response);
    }
}
