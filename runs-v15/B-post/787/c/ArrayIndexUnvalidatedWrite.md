## Verdict

exploitable

## Source

The untrusted `playerIndex` value arrives from the network packet as a `uint32_t` decoded in `decode_score_update()` at line 20-21. It is read directly from untrusted wire data with no bounds validation.

## Fix

**Vulnerable code:**
```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    scoreTable[msg.playerIndex] = msg.newScore;  // No bounds check on playerIndex
}
```

**Fixed code:**
```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    // Validate index is within bounds before writing
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Reject out-of-bounds index
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The vulnerability arises because `msg.playerIndex` is read directly from untrusted network data as a `uint32_t` and used as an array index without validation. Since `scoreTable` is a fixed-size array with only `MAX_PLAYERS` (16) elements, an attacker can supply any `uint32_t` value to cause a write past the end of the buffer, corrupting adjacent memory. The fix adds an explicit bounds check that rejects any index >= `MAX_PLAYERS` before the array access occurs. This ensures the write stays within the destination's allocated bounds and matches the C guidance principle: "Valid indices are `0` to `size - 1`."

## Behaviour changes

none
