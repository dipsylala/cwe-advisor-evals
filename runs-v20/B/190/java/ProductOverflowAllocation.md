## Verdict

exploitable

## Source

`request.getParameter("count")` and `request.getParameter("size")` (HTTP request parameters), parsed with `Integer.parseInt` at lines 14-15.

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
    private static final int MAX_BUFFER_BYTES = 10_000_000;

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // Widen to long before multiplying so the product cannot wrap in 32-bit
        // int arithmetic, and use the *Exact form so any residual overflow is
        // reported rather than silently wrapped.
        long total = Math.multiplyExact((long) count, (long) size);

        // Application-level sanity cap: even a non-overflowing product can
        // request an unreasonably large allocation (a legitimate int product
        // can reach 2^31-1 bytes, well past what this endpoint should hand out).
        if (total > MAX_BUFFER_BYTES)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] buffer = new byte[(int) total];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
}
```

## Explanation

`count` and `size` are each bounded to `[0, 100000]` before the sink, but that per-operand check does not bound their product: `100000 * 100000 = 10,000,000,000`, which is more than four times `Integer.MAX_VALUE` (2,147,483,647). Because `count * size` is evaluated as 32-bit `int` arithmetic, the true product wraps silently - it can land on a small positive value (allocating a far smaller buffer than the request implies and reporting that wrapped size back to the caller as `buffer.length`), on a large positive value within `int` range but still far larger than the endpoint should ever hand out, or on a negative value that would throw `NegativeArraySizeException`. The fix widens both operands to `long` before multiplying and uses `Math.multiplyExact`, so the multiplication itself can no longer wrap in 32 bits and any genuine overflow raises `ArithmeticException` instead of returning a wrapped result. Because the operands are already bounded such that their `long` product cannot exceed `long` range, `multiplyExact` will not itself throw here - the exact-arithmetic form documents and future-proofs the calculation rather than being the only control. The second, independent check (`total > MAX_BUFFER_BYTES`) enforces an application-level sanity cap on the result, since a non-overflowing product can still be an unreasonable allocation size; only after both checks pass is the value narrowed back to `int` for the array allocation, so the narrowing itself is safe.

## Behaviour changes

- Requests where `count * size` previously wrapped to a small positive `int` (e.g. `count=100000, size=42950` overflowing to a small buffer) now receive `400 Bad Request` instead of a response reporting an undersized, silently-wrapped buffer length. This is the security-relevant behaviour the fix is meant to close.
- Requests where `count * size` previously produced a large positive `int` or triggered `NegativeArraySizeException` (an unhandled exception surfacing as a container-level 500) now receive a controlled `400 Bad Request` instead. This is an intentional consequence of validating the result before allocation, not a new restriction on any request that previously succeeded.
- Requests whose validated `count`/`size` combination stays within the existing per-operand bounds but produces a product over the added `MAX_BUFFER_BYTES` (10,000,000) sanity cap now receive `400 Bad Request`. No combination of `count` and `size` within `[0, 100000]` that exceeds this cap could have completed successfully before either (it would overflow, wrap, or attempt a multi-gigabyte allocation), so this does not narrow the set of requests that previously worked.
- No change to the response body or status for any request whose product was already within the new 10,000,000-byte cap; `buffer.length` is still echoed back unchanged for those.

Verification: compiled the fixed file with `javac` (JDK 26) against minimal stub definitions of `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` (the servlet API is not on this environment's classpath) in a scratch directory outside the codebase - compiled cleanly with no errors or warnings. `Math.multiplyExact(long, long)` is a `java.lang.Math` standard-library method (Java 8+), matching the loaded CWE-190 Java guidance.
