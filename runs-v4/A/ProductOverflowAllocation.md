# CWE-190 - ProductOverflowAllocation.java

- **cwe_id**: CWE-190 (Integer Overflow or Wraparound)
- **location**: `evals/cases/190/java/ProductOverflowAllocation/ProductOverflowAllocation.java`, line 24
- **taint source**: `request.getParameter("count")` and `request.getParameter("size")` (lines 14-15), parsed to `int`
- **sink**: `new byte[count * size]` (line 24)
- **confidence**: high - source, sink and the arithmetic between them are all in one method, with no intervening calls

## Verdict

`exploitable`.

The guard on lines 17-21 bounds each operand independently (`0 <= count <= 100000`, `0 <= size <= 100000`) but never bounds their product. The maximum admissible product is `100000 * 100000 = 10_000_000_000`, well past `Integer.MAX_VALUE` (2147483647), so the multiplication on line 24 is evaluated in `int` and wraps silently before it ever reaches the array allocation.

Two concrete requests that pass validation:

- `count=65536&size=65536` - the true product is 2^32, which wraps to exactly `0`. The handler allocates a zero-length buffer and reports `0` for a request that asked for 4 GiB. The size check that was meant to make the allocation meaningful has been defeated by the same wraparound it sits in front of.
- `count=100000&size=42950` - the true product is 4,295,000,000, which wraps to `32704`. A request for ~4 GiB silently yields a 32 KB buffer.

Neither operand check fires, no exception is thrown, and the allocation succeeds with a size unrelated to what was requested. Because `int` overflow in Java is defined wraparound rather than undefined behaviour, this is a deterministic logic error, not a compiler-dependent one - the JVM's `NegativeArraySizeException` only catches the subset of wraps that land negative, and neither example above does.

The bounds are also loose enough that a *non*-overflowing product is already unreasonable: `count=100000&size=20000` multiplies cleanly to 2,000,000,000 and asks the JVM for a 2 GB array on a single unauthenticated request. Overflow is the reported weakness; an uncapped product is the same allocation reaching the same sink by a different route, so the fix closes both.

## Source

Vulnerable code as it stands (lines 9-28):

```java
    private static final int MAX_COUNT = 100000;
    private static final int MAX_SIZE = 100000;

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        // Each operand is bounded, but the PRODUCT is not - 100000 * 100000 exceeds
        // Integer.MAX_VALUE, so this check does not constrain the allocation size.
        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        // CWE-190: int * int wraps silently. count=65536, size=65536 -> 0.
        byte[] buffer = new byte[count * size];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
```

Sink contract, established before changing anything, so the fix can preserve it:

- **Returns** - a `byte[]` whose `length` is written to the response body as decimal text with content type `text/plain`.
- **Discards** - nothing; the buffer's length is the entire response.
- **Arguments left implicit** - none; `new byte[]` takes a single size operand.
- **Failure behaviour** - on the rejection path the handler sets `SC_BAD_REQUEST` and returns without writing a body. `Integer.parseInt` throws `NumberFormatException` on a missing or non-numeric parameter, propagating out of `handle`. That is pre-existing behaviour unrelated to the overflow and is deliberately left alone.

## Fix

```java
    private static final int MAX_COUNT = 100000;
    private static final int MAX_SIZE = 100000;
    private static final int MAX_TOTAL_BYTES = 10 * 1024 * 1024;

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        int total;
        try
        {
            total = Math.multiplyExact(count, size);
        }
        catch (ArithmeticException e)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if (total > MAX_TOTAL_BYTES)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] buffer = new byte[total];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
```

`Math.multiplyExact` is `java.lang.Math`, Java 8+ - no new dependency, no import, nothing to add to `pom.xml` or `build.gradle`. There is no library recommendation for this finding and therefore no version to check against SCA data.

An equivalent formulation, if the codebase prefers to avoid exceptions for control flow, is to widen before multiplying and narrow after the cap check: compute `long total = (long) count * size;` - the cast must be on an operand, not on the result, because `(long) (count * size)` wraps in `int` first and then widens the already-wrong value - then reject `total > MAX_TOTAL_BYTES` and use `Math.toIntExact(total)` at the allocation. Both close the weakness identically; `Math.multiplyExact` is the more direct expression of intent.

## Explanation

The allocation size was computed with a plain `int` multiply on two attacker-supplied operands whose individual bounds permit a product roughly four times `Integer.MAX_VALUE`, so the arithmetic wrapped before any code could inspect it and the resulting array bore no relation to the size requested. `Math.multiplyExact` performs the same multiplication but throws `ArithmeticException` rather than wrapping, which converts a silent wrong answer into an explicit rejection - the check now happens *during* the operation instead of on an already-corrupted result, which is the distinction that matters here: a post-hoc test such as `if (count * size > MAX_TOTAL_BYTES)` would be evaluated on the wrapped value and would wave through the exact `65536 * 65536 -> 0` case that motivates the finding. The `MAX_TOTAL_BYTES` cap is applied to the verified-non-overflowing product and closes the remaining half of the problem, since a product that never overflows can still be a 2 GB allocation driven by one unauthenticated request; the application's own maximum belongs alongside the type's, and the oversized request is rejected rather than clamped, so an over-cap request gets a 400 instead of a silently truncated buffer.

**Behaviour changes beyond closing the weakness:**

- `MAX_TOTAL_BYTES` constant and its check are new. Reason: the operand bounds admit products up to 10^10, so overflow safety alone still leaves an unbounded-allocation path to the same sink. Requests with a product above 10 MiB now receive `SC_BAD_REQUEST` where they previously received either a wrapped length or a multi-gigabyte allocation attempt.
- The overflowing inputs that previously returned `200` with a nonsense length now return `400` with no body. This is the intended correction, and it reuses the handler's existing rejection path verbatim rather than introducing a new error shape.
- The `ArithmeticException` is caught and mapped to the same `SC_BAD_REQUEST`. Reason: an uncaught exception escaping `handle` would surface as a 500 and potentially a stack trace, trading an integer overflow for an information-disclosure and availability problem. Catching it keeps invalid input on the path the method already uses for invalid input.
- The success path is otherwise untouched: same `text/plain` content type, same `Integer.toString(buffer.length)` body, same `buffer` variable and allocation expression shape, same brace-on-own-line style and 4-space indentation, no new imports. Every request that was previously handled correctly still produces a byte-identical response.

**Assumptions** (resolved without asking, since no developer was available to confirm):

- `MAX_TOTAL_BYTES` is set to 10 MiB as a placeholder. The correct ceiling depends on the endpoint's purpose, its concurrency, and the container's heap - none of which are visible in this file. The value should be reviewed against the real workload; the *presence* of a result cap is the security-relevant part, its exact magnitude is a capacity decision.
- `MAX_COUNT` and `MAX_SIZE` are left at their current values. Tightening them would be an alternative fix (any pair whose product fits in an `int` removes the overflow), but that changes the endpoint's accepted input range, which is a product decision rather than a security one. Bounding the product leaves the documented per-operand contract intact.
- Confidence is high on the trace and the fix; the one lower-confidence element is the cap magnitude noted above, which is a tuning value and not a correctness question.

**Verification:** re-run the scanner to confirm the finding is closed, and add boundary tests driving `count=65536&size=65536` (the wrap-to-zero pair), `count=100000&size=42950` (wrap to a small positive), `count=100000&size=20000` (no overflow, over cap), and a valid in-range pair - asserting `400` for the first three and the correct byte count for the last.
