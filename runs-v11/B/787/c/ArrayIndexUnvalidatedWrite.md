## Verdict

Exploitable. The array index `msg.playerIndex` is written directly from untrusted network input without validation against the destination array's bounds.

## Source

The untrusted source is the `packet` parameter passed to `apply_score_update()`. The `packet` is deserialized by `decode_score_update()`, which extracts a 32-bit unsigned integer into `msg.playerIndex` via `memcpy()`. This value originates from a game client over the network and is not validated.

## Fix

**Vulnerable code:**
```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    scoreTable[msg.playerIndex] = msg.newScore;
}
```

**Fixed code:**
```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    // Validate index is within bounds before write
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Reject out-of-bounds index
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds a bounds check before the array write. The condition `msg.playerIndex >= MAX_PLAYERS` validates that the index falls within the valid range [0, MAX_PLAYERS - 1] for an array of size `MAX_PLAYERS` (16 elements). This directly closes CWE-787: the write is now rejected rather than performed out of bounds when the untrusted index exceeds the array's allocated capacity. The check is placed immediately after deserialization and before the sink, making the validation explicit and impossible to bypass.

## Behaviour changes

None. The original code silently writes out of bounds; the fixed code silently returns on an invalid index. The caller receives no error return value in either case. If error reporting is required, the function signature would need to change (e.g., return an `int` status code), but that is a design decision outside the scope of closing the bounds violation. The fix preserves the function's existing return type and calling contract.
