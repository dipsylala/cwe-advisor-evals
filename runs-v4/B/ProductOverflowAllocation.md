# CWE-190: Integer Overflow or Wraparound - ProductOverflowAllocation.java

- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **Location**: `evals/cases/190/java/ProductOverflowAllocation/ProductOverflowAllocation.java`, line 24
- **Confidence**: high

## Verdict

Exploitable.

The two request parameters are each range-checked in isolation, but their product is not. `count` and `size` are both allowed up to `100000`, so `count * size` can reach 10,000,000,000 - far beyond the `Integer.MAX_VALUE` (2,147,483,647) ceiling of the `int` expression. The multiplication is performed in `int` and wraps silently before it ever reaches `new byte[...]`, so the per-operand guard above it does not constrain the allocation at all.

Two distinct outcomes are reachable, both from valid, in-range inputs:

- **Wrap to a smaller positive value.** `count=100000, size=100000` wraps to `1410065408`. The handler allocates a ~1.35 GB buffer instead of the ~9.3 GB requested and reports `1410065408` back to the caller as though that were the requested size. The buffer is silently the wrong length, and downstream code that trusts the size relationship is working from a false premise.
- **Wrap to a negative value.** `count=100000, size=30000` wraps to `-1294967296`. `new byte[-1294967296]` throws `NegativeArraySizeException`, which is unhandled here and escapes the servlet as a 500.

Either way, the check the code relies on has been bypassed by arithmetic, not by an invalid input. The allocation is also large enough to be a memory-pressure lever on its own: even the non-wrapping maximum permitted by the current guard is a multi-hundred-megabyte allocation per request.

## Source

- **Source**: `request.getParameter("count")` and `request.getParameter("size")` (lines 14-15) - attacker-controlled HTTP query/form parameters, parsed to `int` via `Integer.parseInt`.
- **Propagation**: both values pass the per-operand bounds check at lines 17-21 (`0 <= count <= 100000`, `0 <= size <= 100000`). The check constrains each operand but never the product, so it does not break the path.
- **Sink**: `new byte[count * size]` (line 24) - the wrapped `int` product sizes a heap array allocation.
- **Sink contract as written**: returns a `byte[]` whose `length` is written to the response body as text; discards nothing; takes no implicit arguments or defaults; fails with an unhandled `NegativeArraySizeException` (negative wrap) or `OutOfMemoryError` (large positive) that propagates out of `handle`. The invalid-input path already in the method answers with `SC_BAD_REQUEST` and no body.

## Fix

No library change is required - `Math.toIntExact` is in `java.lang` and available on Java 8+.

### Vulnerable code

```java
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

        // Operands are bounded individually, but count * size is evaluated in int
        // and wraps before it reaches the allocation - the guard above never sees the product.
        byte[] buffer = new byte[count * size];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
```

### Fixed code

```java
    private static final int MAX_COUNT = 100000;
    private static final int MAX_SIZE = 100000;
    private static final int MAX_TOTAL_BYTES = 16 * 1024 * 1024;

    public void handle(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        int count = Integer.parseInt(request.getParameter("count"));
        int size = Integer.parseInt(request.getParameter("size"));

        if (count < 0 || count > MAX_COUNT || size < 0 || size > MAX_SIZE)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        long totalBytes = (long) count * size;

        if (totalBytes > MAX_TOTAL_BYTES)
        {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        byte[] buffer = new byte[Math.toIntExact(totalBytes)];

        response.setContentType("text/plain");
        response.getWriter().write(Integer.toString(buffer.length));
    }
```

Widening one operand is what moves the multiply out of `int`; on Java 9+ `Math.multiplyFull(count, size)` expresses the same thing more explicitly and can be substituted directly. `Math.multiplyExact(count, size)` is the alternative shape if an `ArithmeticException` is preferred over an explicit size cap - but it only rejects products above `Integer.MAX_VALUE`, so the cap check would still be needed to keep a 2 GB allocation off a single request.

`MAX_TOTAL_BYTES` is set to 16 MiB as a placeholder for whatever this endpoint's real maximum response buffer is; set it to the application's actual limit before merging. Any value at or below `Integer.MAX_VALUE` keeps the fix sound.

### Verification

Drive the handler with `count=100000, size=100000` (previously wrapped positive to `1410065408`) and `count=100000, size=30000` (previously wrapped negative to `-1294967296`) and assert a 400 in both cases rather than a successful allocation or a 500. Add `count=0x40000000, size=4` at the boundary if the per-operand caps are ever raised, since that pair wraps to exactly zero. Confirm a normal in-range request - say `count=1000, size=1000` - still returns 200 with body `1000000`.

## Explanation

The multiplication was being evaluated in `int` arithmetic, where Java wraps silently rather than signalling, so the product overflowed before the allocation and before any check could observe it. Casting one operand to `long` moves the multiply into 64-bit arithmetic, where the largest product the per-operand guards permit (10,000,000,000) is represented exactly and cannot wrap; the result is then compared against an explicit total-size limit and rejected through the same `SC_BAD_REQUEST` path the method already uses for invalid input. `Math.toIntExact` performs the narrowing back to the `int` the array constructor needs, and would throw rather than truncate silently if the cap were ever misconfigured above `Integer.MAX_VALUE`, so the two checks cannot drift apart. The result is that the allocation size is now the value that was actually validated, and an oversized request is answered with a client error instead of a wrongly-sized buffer or an unhandled exception.

## Behaviour changes

- **Requests whose `count * size` exceeds `MAX_TOTAL_BYTES` now return 400 with no body.** Previously, depending on how the product wrapped, they either returned 200 with a wrong buffer length in the body or propagated an unhandled `NegativeArraySizeException` out of `handle` as a 500. This is the weakness being closed, but it is a visible response change for those inputs: any caller relying on a large request succeeding will now see a rejection. The rejection reuses the existing invalid-input branch, so its status code and empty-body shape match what the method already emits.
- **New constant `MAX_TOTAL_BYTES` (16 MiB, assumed).** Needed to cap the allocation independently of overflow safety - without it, a request could still legitimately ask for a non-wrapping ~2 GB buffer. The value is not derivable from the file and is an assumption; a reviewer should replace it with the endpoint's real limit. Raising it up to `Integer.MAX_VALUE` narrows the set of newly rejected requests without weakening the overflow fix.
- **Requests at or below the cap are unchanged**: same buffer length, same `text/plain` content type, same numeric body, same 200. The sink still returns a `byte[]` whose `length` is written to the response, discards nothing, and supplies no argument the original left implicit.
- **No change to the `Integer.parseInt` failure path.** A non-numeric or absent `count`/`size` still throws `NumberFormatException` out of `handle` exactly as before. That is a pre-existing input-handling gap unrelated to CWE-190 and was left alone to keep the diff scoped to the reported finding; it is worth raising separately.
- **No change to the per-operand `MAX_COUNT`/`MAX_SIZE` guard.** It is retained as-is; the product check is added after it rather than replacing it, so the earlier, clearer per-field rejection still fires first.

## Assumptions

- `MAX_TOTAL_BYTES = 16 * 1024 * 1024` was chosen without a stated application limit to size against. Any value at or below `Integer.MAX_VALUE` preserves the overflow fix; only the set of requests rejected as oversized changes.
- Rejecting over-cap requests with the existing `SC_BAD_REQUEST` path was chosen over clamping the size or introducing a new status code, on the basis that the method already answers out-of-range input that way. Rejecting rather than clamping is deliberate: a clamped allocation would reintroduce the original defect of reporting a length the caller did not ask for.
- `(long) count * size` was used rather than `Math.multiplyFull` so the fix compiles on Java 8, since the `javax.servlet` imports suggest a pre-Jakarta stack of unknown JDK level.
