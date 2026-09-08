## Verdict
The integer overflow vulnerability is real. Multiplication of two bounded 32-bit integers (each ≤ 100000) can exceed `Integer.MAX_VALUE` without detection, wrapping to an unexpected value and creating an undersized buffer allocation or throwing `NegativeArraySizeException`.

## Source
The operands originate from attacker-controlled request parameters (lines 14–15: `Integer.parseInt(request.getParameter("count"))` and `request.getParameter("size")`). Bounds validation on lines 17–21 constrains each operand individually but does not prevent their product from overflowing. The multiplication result (line 24) is used directly as an array size without overflow checking.

## Fix
Replace the unchecked multiplication with `Math.multiplyExact()` and catch `ArithmeticException` to reject oversized requests.

### File: ProductOverflowAllocation.java
```java
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

        // Use Math.multiplyExact to detect integer overflow
        int bufferSize;
        try
        {
            bufferSize = Math.multiplyExact(count, size);
        }
        catch (ArithmeticException e)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] buffer = new byte[bufferSize];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
}
```

## Explanation
The original code validates `count` and `size` individually (0 to 100000) but multiplies them without overflow detection. For example, 100000 × 100000 = 10,000,000,000, which exceeds `Integer.MAX_VALUE` (2,147,483,647). The fix replaces the unchecked multiplication operator with `Math.multiplyExact()`, which throws `ArithmeticException` when the product overflows. Catching this exception allows the application to return HTTP 400 (Bad Request) instead of silently allocating an undersized buffer or throwing `NegativeArraySizeException` at runtime.

`Math.multiplyExact()` has been available since Java 8, making this a reliable standard-library solution. The exception is caught and handled within the same method, so the control flow remains clear and the error is reported to the client immediately.

## Behaviour changes
- **Overflow scenario (e.g., count=100000, size=100000):** Previously would silently wrap or allocate an undersized buffer; now returns HTTP 400 (SC_BAD_REQUEST) immediately.
- **Normal scenario (count and size within safe product range):** No behavioural change; allocation proceeds as before.
- **Side effect:** Adds an exception handler block, but the exception is caught and handled locally with no stack trace exposed to the caller.
