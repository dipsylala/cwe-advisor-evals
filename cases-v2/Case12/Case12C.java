

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case12C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case12D()).handleSink(data , request, response);
    }
}
