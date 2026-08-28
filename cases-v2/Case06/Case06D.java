

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case06D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case06E()).handleSink(data , request, response);
    }
}
