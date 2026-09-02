## Verdict

Exploitable. Confidence: high.

CWE-121, Stack-based Buffer Overflow. `build_audit_message` writes both of its caller-supplied string parameters into a fixed 64-byte stack buffer using unbounded `strcpy`/`strcat`, with no length check against the buffer's capacity beforehand. This is the entire call chain supplied (a single file, no caller present), so `username` and `action` are treated as attacker-controlled/untrusted at the function boundary, per this function's own contract.

## Source

- Source: the `username` and `action` parameters of `build_audit_message` (file `StackAuditMessageOverflow.c`, function signature at lines 4-7) - both are attacker-controlled inputs to this function with no length constraint applied anywhere before use.
- Sink: `char message[64]` (line 9) via `strcpy(message, username)` (line 11), `strcat(message, ":")` (line 12), and `strcat(message, action)` (line 14, the reported finding line). Any of the three writes can individually overflow the 64-byte buffer if the combined length of `username`, `":"`, and `action` (plus the NUL terminator) exceeds 64 bytes; none of the calls carries a size limit tied to `sizeof(message)`.
- Data flow: parameters flow directly into the buffer with no intermediate validation, truncation check, or length comparison - a straight, unguarded taint path from function input to fixed-size stack write.

## Fix

Vulnerable code:

```c
char message[64];

strcpy(message, username);
strcat(message, ":");
// SAST FINDING: CWE-121 (Stack-based Buffer Overflow) reported here. Sink is the next statement.
strcat(message, action);

int written = snprintf(out, out_capacity, "AUDIT %s", message);
if (written < 0 || (size_t)written >= out_capacity) {
    return -1;
}
return 0;
```

Fixed code:

```c
char message[64];

int msg_len = snprintf(message, sizeof(message), "%s:%s", username, action);
if (msg_len < 0 || (size_t)msg_len >= sizeof(message)) {
    return -1;
}

int written = snprintf(out, out_capacity, "AUDIT %s", message);
if (written < 0 || (size_t)written >= out_capacity) {
    return -1;
}
return 0;
```

## Explanation

The three unbounded calls (`strcpy` + `strcat` + `strcat`) are replaced with a single bounded `snprintf(message, sizeof(message), "%s:%s", username, action)`, which formats `username`, the `:` separator, and `action` into `message` in one call, using the buffer's own declared size (`sizeof(message)`) rather than trusting the combined input length. `snprintf` never writes past the size it is given and always NUL-terminates within that size, which closes the stack overflow. Per the guidance's preference for rejecting oversized input over silently truncating it, the fix checks `snprintf`'s return value: a negative result or a result `>= sizeof(message)` means the combined input did not fit, and the function returns `-1` instead of proceeding with a truncated (and therefore semantically different) audit message. This mirrors the truncation check the function already performs on the second `snprintf` into `out`, so the error-handling pattern is now applied consistently at both writes.

## Behaviour changes

- New early-return path: if `username` and `action` combined (plus the `:` separator and terminator) do not fit in 64 bytes, the function now returns `-1` before ever building or emitting an audit message. Previously this input would overflow the stack buffer (undefined behaviour: corruption, potential crash, or - unreliably - a truncated/garbled message written to `out`). Reason: this closes the overflow and matches the guidance's directive to reject oversized input rather than truncate it; it also reuses the function's existing `-1`-on-failure return convention, so no new return shape is introduced.
- The literal three-statement construction (`strcpy` then two `strcat` calls) is replaced by one `snprintf` call. No argument, output, or the final `AUDIT %s` formatting into `out` is altered - `out`, `out_capacity`, and the success/failure contract of the function are unchanged for all inputs that fit within `message`'s capacity.
- Assumption: `username` and `action` are treated as untrusted/attacker-influenced, since no caller is present in the supplied file to show otherwise and the function accepts them as plain parameters with no prior validation.
