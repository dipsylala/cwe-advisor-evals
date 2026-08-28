

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case06B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case06C()).handleSink(data , request, response);
    }
}
