## Verdict

Exploitable. `count` and `size` are each individually range-checked (`0..100000`), but the check is applied to the operands, not to their product. Two in-range values (e.g. `count = 100000`, `size = 100000`) multiply to `10,000,000,000`, which exceeds `Integer.MAX_VALUE` (2,147,483,647). The `int * int` multiplication at line 24 wraps silently, and the wrapped result is passed directly to `new byte[...]`, so the size check the developer intended is bypassed by the arithmetic that follows it.

## Source

`request.getParameter("count")` and `request.getParameter("size")`, both attacker-controlled HTTP request parameters, parsed with `Integer.parseInt` at lines 14-15. Each is bounded individually against `MAX_COUNT`/`MAX_SIZE` (100000) at line 17, but no check is applied to `count * size` before it is used.

## Fix

Vulnerable code (line 24):

```java
// SAST FINDING: CWE-190 (Integer Overflow or Wraparound) reported here. Sink is the next statement.
byte[] buffer = new byte[count * size];
```

Fixed code:

```java
int allocationSize;
try
{
    // Fix: detect multiplication overflow explicitly instead of trusting the wrapped result of count * size
    allocationSize = Math.multiplyExact(count, size);
}
catch (ArithmeticException e)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

byte[] buffer = new byte[allocationSize];
```

Full method after the fix:

```java
public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
{
    int count = Integer.parseInt(request.getParameter("count"));
    int size = Integer.parseInt(request.getParameter("size"));

    if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
    {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        return;
    }

    int allocationSize;
    try
    {
        // Fix: detect multiplication overflow explicitly instead of trusting the wrapped result of count * size
        allocationSize = Math.multiplyExact(count, size);
    }
    catch (ArithmeticException e)
    {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        return;
    }

    byte[] buffer = new byte[allocationSize];

    response.setContentType("text/plain");
    response.getWriter().write(Integer.toString(buffer.length));
}
```

## Explanation

`count * size` is plain `int` arithmetic, which wraps silently on overflow in Java instead of raising an error. Because `count` and `size` are validated separately rather than as a combined product, two individually legal values can still multiply past `Integer.MAX_VALUE`, producing a wrapped result that no longer reflects the requested allocation - it can be negative (causing `NegativeArraySizeException`, an uncaught crash) or a small positive number (silently under-allocating relative to what the caller of `handle` presumably intended to represent). Replacing the raw multiplication with `Math.multiplyExact(count, size)` performs the same calculation but throws `ArithmeticException` the instant the true mathematical product exceeds `int` range, so the overflow is detected before it can reach the allocation. The surrounding `try/catch` routes that exception to the same `400 Bad Request` response the existing range check already uses, keeping the rejection behaviour consistent with the rest of the method.

## Behaviour changes

- Added a `try/catch` around the multiplication and an `allocationSize` local to hold its result. Reason: this is the mechanism that converts a silently wrapped product into a caught, explicit rejection - required to close the weakness.
- On an overflowing `count`/`size` pair, the method now returns `400 Bad Request` via the existing `SC_BAD_REQUEST` path instead of either allocating an array with a wraparound-derived size or letting `NegativeArraySizeException` propagate uncaught (which would surface as a 500-level servlet error). This is the intended effect of the fix: the sink's failure behaviour changes from "undefined/crash on overflow" to "controlled 400", matching the response the request would already receive if `count` or `size` individually exceeded their bounds.
- No other change: `buffer`'s type, the `response.setContentType` call, and the `Integer.toString(buffer.length)` write are untouched, so the success-path contract (return the allocated buffer's length as plain text) is preserved exactly for all non-overflowing inputs.
