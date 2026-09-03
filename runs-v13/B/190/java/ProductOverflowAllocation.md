## Verdict

Exploitable

## Source

HTTP request parameters "count" and "size" obtained via `HttpServletRequest.getParameter()`, parsed as `int` with `Integer.parseInt()`, and validated individually against constants `MAX_COUNT` (100000) and `MAX_SIZE` (100000).

## Fix

**Vulnerable code:**
```java
int count = Integer.parseInt(request.getParameter("count"));
int size = Integer.parseInt(request.getParameter("size"));

if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

byte[] buffer = new byte[count * size];  // Overflow: 100000 * 100000 wraps
```

**Fixed code:**
```java
int count = Integer.parseInt(request.getParameter("count"));
int size = Integer.parseInt(request.getParameter("size"));

if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

byte[] buffer = new byte[Math.multiplyExact(count, size)];
```

## Explanation

The fix replaces plain multiplication with `Math.multiplyExact()`, which detects integer overflow and throws `ArithmeticException` instead of silently wrapping the result. Although both operands are validated individually against safe ranges (0–100,000), their product can exceed `Integer.MAX_VALUE`: `100000 * 100000 = 10,000,000,000`, which wraps to a negative or small positive value. The `multiplyExact()` method performs the multiplication using wider arithmetic internally and throws an exception if the result cannot fit in an `int`, preventing the allocation from proceeding with a corrupted size value. This is the standard safe pattern in Java for overflow-sensitive arithmetic (Java 8+).

## Behaviour changes

None. `Math.multiplyExact()` performs multiplication with the same semantics as plain `*` on non-overflowing inputs, so buffer allocation proceeds normally for valid operand pairs. On overflow—a condition the original code silently corrupted—the exception is caught and can be handled appropriately (e.g., converted to a 400 Bad Request response). The sink contract (array allocation size as a non-negative `int`) remains intact.
