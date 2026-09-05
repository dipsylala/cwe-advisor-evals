## Verdict

exploitable

## Source

`frame[0]` at line 39 of ArrayIndexUnvalidatedNetworkOffset.c — untrusted network input read directly into `field_index` without validation.

## Fix

**Vulnerable code:**
```c
    uint8_t field_index = frame[0];

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    *out = descriptors[field_index];
```

**Fixed code:**
```c
    uint8_t field_index = frame[0];

    // Validate field_index is within bounds of the descriptors table
    if (field_index >= MAX_FIELDS) {
        return -1;
    }

    *out = descriptors[field_index];
```

## Explanation

The `field_index` value is read directly from the network frame without validation and used as an array index into the static `descriptors` table. Since `field_index` is an attacker-controlled byte (0–255) and the `descriptors` array has only 16 elements (`MAX_FIELDS`), any index >= 16 reads past the end of the array, violating CWE-125. The fix adds an explicit bounds check immediately before the array access, rejecting out-of-bounds indices. This follows the C-specific guidance: "Check every array index against the array's known bound (0 <= index < length) immediately before the dereference."

## Behaviour changes

The fixed code returns -1 when `field_index >= MAX_FIELDS`, preventing the out-of-bounds read and signalling an error to the caller. This aligns with the existing error-handling pattern in the function and preserves the sink contract: `*out` is only written when the bounds check passes.

