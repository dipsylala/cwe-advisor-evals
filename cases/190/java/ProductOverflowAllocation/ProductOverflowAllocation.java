package evalcases;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProductOverflowAllocation
{
    private static final int MAX_COUNT = 100000;
    private static final int MAX_SIZE = 100000;

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // SAST FINDING: CWE-190 (Integer Overflow or Wraparound) reported here. Sink is the next statement.
        byte[] buffer = new byte[count * size];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
}
