## Verdict

The multiplication `count * size` at line 24 performs unchecked arithmetic on attacker-influenced input. Although each operand is individually bounded (≤ 100,000), their product can reach 10^10, vastly exceeding `Integer.MAX_VALUE` (~2.1 × 10^9). Silent overflow wraps the result to a negative or small positive integer, causing either a caught exception or undersized allocation. The vulnerability is confirmed.

## Source

The unsafe arithmetic occurs at line 24:
```java
byte[] buffer = new byte[count * size];
```

The operands derive from HTTP request parameters (lines 14–15) and are validated individually (line 17) but not as a product. The validation cannot prevent overflow because the check applies before the multiplication, but the check bounds each operand independently, not their combination.

## Fix

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

        try
        {
            byte[] buffer = new byte[Math.multiplyExact(count, size)];

            response.setContentType("text/plain");
            response.getWriter().write(Integer.toString(buffer.length));
        }
        catch (ArithmeticException e)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        }
    }
}
```

## Explanation

`Math.multiplyExact(count, size)` replaces the plain `*` operator. This built-in method (available since Java 8) performs the multiplication and throws `ArithmeticException` if the result overflows, rather than silently wrapping to a negative or truncated value.

The catch block handles the overflow case by returning a 400 Bad Request status, preventing the handler from attempting an allocation with a wrapped size. This satisfies the CWE-190 Java remediation principle: "use `Math.*Exact` for the operation and explicit range validation for the operands."

The individual operand bounds (MAX_COUNT, MAX_SIZE) remain in place as defense-in-depth and to provide a clear error response for invalid individual parameters. The `Math.multiplyExact` call is the primary control that prevents the overflow vulnerability.

## Behaviour changes

**Before fix:**
- Inputs like count=100000, size=100000 cause silent integer overflow.
- The wrapped result (a small or negative integer) reaches the array constructor.
- The JVM throws `NegativeArraySizeException` (if negative) or allocates a tiny buffer (if positive after wrap).
- The handler crashes or behaves unexpectedly without a clear error response.

**After fix:**
- `Math.multiplyExact(100000, 100000)` detects overflow and throws `ArithmeticException`.
- The catch block handles the exception and returns HTTP 400.
- The client receives a clear error status instead of a server crash.
- The application survives the attack with an explicit, auditable rejection.
