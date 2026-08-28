

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case02B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case02C()).handleSink(data , request, response);
    }
}
