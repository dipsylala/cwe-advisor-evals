## Verdict

Integer overflow in array allocation. The multiplication of two user-bounded integers can exceed `Integer.MAX_VALUE` despite individual range validation, resulting in a wrapped value that misrepresents the requested allocation size.

## Source

Lines 14–15: `count` and `size` are parsed from request parameters and validated individually against `MAX_COUNT` and `MAX_SIZE` (100000 each).

Line 24: The product `count * size` is used directly as an array size without overflow checking.

Attack scenario: Both operands at maximum (100000) produce a product of 10,000,000,000, which wraps within `int` range to a small or negative value, resulting in either a `NegativeArraySizeException` or allocation of far fewer bytes than requested.

## Fix

Replace the unchecked multiplication with `Math.multiplyExact`, which throws `ArithmeticException` on overflow:

```java
byte[] buffer = new byte[Math.multiplyExact(count, size)];
```

If overflow-triggered exceptions should be handled gracefully, wrap in try-catch:

```java
try {
    byte[] buffer = new byte[Math.multiplyExact(count, size)];
    response.setContentType("text/plain");
    response.getWriter().write(Integer.toString(buffer.length));
} catch (ArithmeticException e) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
}
```

## Explanation

`Math.multiplyExact(count, size)` performs the same multiplication as `count * size` but throws `ArithmeticException` instead of silently wrapping on overflow. This converts a logic error (wrong-sized buffer) into a catchable exception, allowing the application to reject the request explicitly. Individual range checks on `count` and `size` remain insufficient because two individually valid operands can still produce an overflowing product; pre-operation overflow detection (via `Math.multiplyExact`) is the correct pattern per CWE-190 Java guidance.

## Behaviour changes

- Requests with operands whose product exceeds `Integer.MAX_VALUE` now throw `ArithmeticException` instead of silently creating a wrong-sized buffer.
- If the exception is uncaught, it propagates to the container's default error handler; if caught (as shown in the fix), the response returns HTTP 400 Bad Request.
- Successful allocations (products within valid range) are unaffected; buffer size remains the same.
