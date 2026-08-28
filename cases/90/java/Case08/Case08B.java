

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case08B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case08C()).handleSink(data , request, response);
    }
}
