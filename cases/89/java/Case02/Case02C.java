

package evalcases;
import testcasesupport.*;

import javax.servlet.http.*;

public class Case02C
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        (new Case02D()).handleSink(data , request, response);
    }
}
