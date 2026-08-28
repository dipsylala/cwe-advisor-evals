

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case11C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case11D()).handleSink(data , request, response);
    }
}
