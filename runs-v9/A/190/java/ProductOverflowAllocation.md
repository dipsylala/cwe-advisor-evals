## Verdict

Confirmed. `count` and `size` are each bounded to `[0, 100000]` individually, but their product is not bounded before it is used as the array length. `100000 * 100000 = 10,000,000,000`, which exceeds `Integer.MAX_VALUE` (2,147,483,647). The `int * int` multiplication wraps around (silently producing a smaller, even negative, 32-bit value) before it is passed to `new byte[...]`, so the allocation size at line 24 does not reflect the attacker-supplied `count` and `size` values.

## Source

`request.getParameter("count")` and `request.getParameter("size")` (lines 14-15), both attacker-controlled HTTP request parameters, parsed to `int` and range-checked only individually (line 17) before being multiplied together.

## Fix

```java
package evalcases;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ProductOverflowAllocation
{
    private static final int MAX_COUNT = 100000;
    private static final int MAX_SIZE = 100000;
    private static final long MAX_BUFFER_BYTES = 10_000_000L; // sane cap for this endpoint

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        long totalBytes = (long) count * (long) size;

        if (totalBytes > MAX_BUFFER_BYTES)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] buffer = new byte[(int) totalBytes];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
}
```

## Explanation

The individual range checks on `count` and `size` are necessary but not sufficient: they bound each factor, not their product, so the multiplication at line 24 (`count * size`) is still performed entirely in 32-bit `int` arithmetic and can overflow even though both operands passed validation.

The fix widens the multiplication to `long` by casting each operand before multiplying (`(long) count * (long) size`), which computes the true mathematical product without wraparound. That product is then checked against an explicit upper bound (`MAX_BUFFER_BYTES`) chosen to reflect a reasonable maximum allocation for this endpoint, rather than relying on `Integer.MAX_VALUE` alone — an allocation near 2 GB would pass an `Integer.MAX_VALUE` check but is still an unreasonable, potential-DoS allocation size for a single request. Only after the product is confirmed to be within the sane bound is it narrowed back to `int` for the array-length argument, which is safe at that point because the bound is well within `int` range.

This preserves the existing early-return/400 pattern used for the individual parameter checks, so the control flow and response behavior on invalid input stay consistent with the rest of the method.
