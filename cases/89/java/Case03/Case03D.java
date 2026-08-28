

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case03D
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case03E()).handleSink(data , request, response);
    }
}
