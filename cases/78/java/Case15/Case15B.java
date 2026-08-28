

package evalcases;

import testcasesupport.*;

import javax.servlet.http.*;

public class Case15B
{
    public void handleSink(String data , HttpServletRequest request, HttpServletResponse response) throws Throwable
    {

        String osCommand;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {
            
            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {
            
            osCommand = "/bin/ls ";
        }

        
        // SAST FINDING: CWE-78 (OS Command Injection) reported here. Sink is the next statement.
        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();

    }
}
