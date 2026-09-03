## Verdict

Real issue. The array index `msg.playerIndex` derives directly from untrusted network input without bounds validation, allowing an out-of-bounds write to `scoreTable`.

## Source

```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    scoreTable[msg.playerIndex] = msg.newScore;  // Line 34: no bounds check
}
```

The `scoreTable` is declared as `static int scoreTable[MAX_PLAYERS]` with `MAX_PLAYERS = 16`. The `playerIndex` field is unpacked from the network packet without validation, so a malicious client can supply any `uint32_t` value.

## Fix

```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Reject out-of-bounds index
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

CWE-787 occurs when a write target's bounds are not validated before use. Here, `msg.playerIndex` is read from an untrusted network source and used directly as an array index without checking whether it falls within `[0, MAX_PLAYERS)`.

The fix validates the index against the array bounds. If `playerIndex` is greater than or equal to `MAX_PLAYERS`, the function rejects the message and returns early, preventing the out-of-bounds write. This is the primary defense: rejecting invalid input rather than attempting to sanitize or clamp it.
