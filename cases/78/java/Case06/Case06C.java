

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case06C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case06D()).handleSink(data , request, response);
    }
}
