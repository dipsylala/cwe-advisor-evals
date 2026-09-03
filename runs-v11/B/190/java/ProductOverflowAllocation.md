## Verdict
exploitable

## Source
HTTP request parameters `count` and `size` (lines 14-15), parsed from user input without overflow validation.

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

// SAST FINDING: CWE-190 (Integer Overflow or Wraparound) reported here.
byte[] buffer = new byte[count * size];
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

// Prevent integer overflow: verify count * size won't exceed Integer.MAX_VALUE
if (count > 0 && size > Integer.MAX_VALUE / count)
{
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    return;
}

byte[] buffer = new byte[count * size];
```

## Explanation
The operand-level validation (lines 17-21) ensures `count` and `size` are individually bounded to [0, 100000], but does not prevent their product from overflowing. Multiplying two values each up to 100,000 yields 10,000,000,000, which far exceeds `Integer.MAX_VALUE` (2,147,483,647). The unchecked multiplication wraps to an incorrect value, potentially allocating a small buffer where a large one was intended.

The fix adds a pre-multiplication overflow check: when `count > 0`, it verifies that `size` does not exceed `Integer.MAX_VALUE / count`. This check prevents the multiplication from wrapping. If the check fails, the handler rejects the request with HTTP 400, the same status it returns for out-of-range operands, maintaining consistent error signaling.

## Behaviour changes
None. The fix preserves the original method's contract: it returns either HTTP 200 with the buffer content, or HTTP 400 for invalid input. The overflow check is inserted as an additional gate in the validation logic, not altering control flow when valid values are provided. The multiplication itself remains unchanged (no conversion to `Math.multiplyExact`), and the allocation preserves the original size calculation for all valid inputs.
