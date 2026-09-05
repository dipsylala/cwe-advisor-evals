## Verdict

exploitable

## Source

Lines 14-15 parse user-controlled parameters:
- `int count = Integer.parseInt(request.getParameter("count"));`
- `int size = Integer.parseInt(request.getParameter("size"));`

The validation at lines 17-21 constrains each individually to [0, 100000], but does not prevent overflow of their product.

Data flows to the sink at line 24.

## Fix

**Vulnerable code (line 24):**
```java
byte[] buffer = new byte[count * size];
```

**Fixed code:**
```java
byte[] buffer = new byte[Math.multiplyExact(count, size)];
```

## Explanation

The vulnerability is an integer overflow in the multiplication `count * size`. Although both operands are validated individually (lines 17-21), their product can reach 100000 × 100000 = 10,000,000,000, which exceeds `Integer.MAX_VALUE` (2,147,483,647). When this overflow occurs, the result wraps to a negative or small positive number. This can lead to a `NegativeArraySizeException` or unexpected allocation behavior. Replacing the plain multiplication with `Math.multiplyExact()` (available in Java 8+) throws `ArithmeticException` if overflow would occur, making the problem explicit rather than silent.

## Behaviour changes

The multiplication now throws `ArithmeticException` on overflow, changing the failure mode from silent wraparound to an explicit exception. This will propagate as an HTTP 500 error instead of succeeding with an incorrect allocation. This is the correct behavior—an attacker requesting `count=100000, size=100000` should receive an error, not have their request succeed with an undersized allocation. The change from `int` arithmetic to the checked `Math.multiplyExact()` method preserves the return type and contract; it only adds overflow detection.
