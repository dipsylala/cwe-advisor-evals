

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case03B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case03C()).handleSink(data , request, response);
    }
}
