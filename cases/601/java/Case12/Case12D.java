

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case12D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case12E()).handleSink(data , request, response);
    }
}
