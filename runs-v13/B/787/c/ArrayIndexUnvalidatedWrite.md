## Verdict

Exploitable. The `msg.playerIndex` value arrives from untrusted network input without validation against the `scoreTable` array bounds (MAX_PLAYERS = 16). An attacker can send a packet with an index value >= 16 or negative, causing an out-of-bounds write.

## Source

The source is the `packet` parameter in `apply_score_update()` at line 29, which receives data from the network read loop (per the comment on lines 24-27). The packet contents are decoded via `memcpy()` into a `ScoreUpdateMsg` structure, extracting `msg.playerIndex` at lines 19-21. That value flows directly to the array sink without validation.

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

    // Validate the player index before writing.
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Invalid player index, reject the update.
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds an explicit bounds check before the array write, ensuring the player index stays within the valid range [0, MAX_PLAYERS). Per the C-language guidance for CWE-787, valid array indices are 0 to size-1, and a write whose index comes from untrusted input must be validated against the actual destination capacity before the write occurs. This check prevents an attacker from using an out-of-range `playerIndex` to corrupt adjacent memory. The function returns early if the index is invalid, rejecting the update rather than attempting a truncated write.

## Behaviour changes

None. The sink's contract (a void return, no produced output) remains intact. The function rejects invalid packets rather than performing them, which is the correct behaviour for untrusted network input.
