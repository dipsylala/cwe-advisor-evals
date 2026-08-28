

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import java.util.logging.Level;

public class Case19A extends AbstractTestCaseServlet
{
    private void handle(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        
        data = "foo";

        (new Case19B()).handleSink(data , request, response );
    }
}
