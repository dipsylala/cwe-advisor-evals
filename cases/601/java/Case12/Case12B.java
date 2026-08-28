

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case12B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case12C()).handleSink(data , request, response);
    }
}
