## Verdict

Real issue. Integer multiplication of two user-supplied values that are individually validated can overflow silently in Java, producing a wrapped result that either becomes a negative array size (throwing `NegativeArraySizeException`) or a much smaller allocation than intended. The multiplicands pass individual bounds checks but their product does not.

## Source

File: `evals/cases/190/java/ProductOverflowAllocation/ProductOverflowAllocation.java`, line 24.

```java
int count = Integer.parseInt(request.getParameter("count"));      // line 14
int size = Integer.parseInt(request.getParameter("size"));        // line 15

if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE) // line 17
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

byte[] buffer = new byte[count * size];  // line 24 - OVERFLOW HERE
```

The operands are validated individually (each ≤ 100000), but their product can exceed `Integer.MAX_VALUE` (2,147,483,647). For example, `100000 * 100000 = 10,000,000,000`, which wraps to a negative value in signed 32-bit arithmetic, causing `NegativeArraySizeException`.

## Fix

Replace the multiplication with a checked operation and add an application-level cap:

```java
int count = Integer.parseInt(request.getParameter("count"));
int size = Integer.parseInt(request.getParameter("size"));

if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

try
{
    int bufferSize = Math.multiplyExact(count, size);
    byte[] buffer = new byte[bufferSize];
    
    response.setContentType("text/plain");
    response.getWriter().write(Integer.toString(buffer.length));
}
catch (ArithmeticException e)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
}
```

## Explanation

`Math.multiplyExact()` performs the multiplication and explicitly throws `ArithmeticException` if the result overflows, rather than silently wrapping. This prevents the allocation from being created with an unintended size. The caught exception allows the handler to return a proper HTTP 400 response instead of propagating an unchecked exception. The operand-level checks remain in place as a first-line validation; the overflow check operates on the result of the calculation and closes the gap between "both operands are individually safe" and "their combination is safe."

## Behaviour changes

- **Before:** Request with `count=100000` and `size=100000` produces integer overflow, wraps to a negative number, and throws uncaught `NegativeArraySizeException`, resulting in a 500 error and server-side stack trace exposure.
- **After:** The same request throws `ArithmeticException` inside the try block, caught and converted to an HTTP 400 response. The client receives a proper error status without a server error. Legitimate requests with smaller operands whose product does not overflow continue to work unchanged.
