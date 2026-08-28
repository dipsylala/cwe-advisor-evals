

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case03C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case03D()).handleSink(data , request, response);
    }
}
