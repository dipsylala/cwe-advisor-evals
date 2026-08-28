

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case11B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case11C()).handleSink(data , request, response);
    }
}
