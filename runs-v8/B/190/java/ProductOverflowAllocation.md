## Verdict

Confirmed. The multiplication at line 24 can overflow even when both operands pass individual bounds checks.

## Source

Lines 14-15: Request parameters `count` and `size` are parsed as `int` values. Lines 17-21 validate each against `MAX_COUNT` and `MAX_SIZE` (both 100,000) independently. Line 24 multiplies them without checking the product.

The attack: request `count=100000` and `size=100000`. Both pass validation. Their product is 10,000,000,000, which exceeds `Integer.MAX_VALUE` (2,147,483,647) and wraps to a negative value (specifically -2,147,483,648 in two's complement). The allocation fails with `NegativeArraySizeException`.

## Fix

Replace the unsafe multiplication with `Math.multiplyExact()`:

```java
int bufferSize = Math.multiplyExact(count, size);
byte[] buffer = new byte[bufferSize];
```

Alternatively, wrap in try-catch to handle overflow gracefully:

```java
try {
    int bufferSize = Math.multiplyExact(count, size);
    byte[] buffer = new byte[bufferSize];
    
    response.setContentType("text/plain");
    response.getWriter().write(Integer.toString(buffer.length));
} catch (ArithmeticException e) {
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}
```

## Explanation

`Math.multiplyExact()` throws `ArithmeticException` when the result overflows `int` range, replacing silent wraparound with a caught exception. This prevents the wrapped negative value from reaching the array allocation. Individual operand validation is necessary but insufficient—validating each operand against a maximum does not prevent their product from overflowing. The fix validates the result of the multiplication before use.

## Behaviour changes

- **Normal case (count=1000, size=1000)**: `Math.multiplyExact(1000, 1000)` returns 1,000,000 as before; array allocation succeeds.
- **Overflow case (count=100000, size=100000)**: `Math.multiplyExact(100000, 100000)` throws `ArithmeticException` instead of silently wrapping to -2,147,483,648. Request now fails safely rather than with `NegativeArraySizeException` buried in the JVM. With try-catch, HTTP 400 is returned to the client.
- **Edge case (count or size = 0)**: Both pass validation; multiplication result is 0; array allocation succeeds as before.

