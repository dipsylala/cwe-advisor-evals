

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case08C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case08D()).handleSink(data , request, response);
    }
}
