## Verdict

Real issue. The `playerIndex` field extracted from an untrusted network packet is written directly as an array index without bounds checking, permitting out-of-bounds memory writes to `scoreTable`.

## Source

Line 34 in `apply_score_update()`:
```c
scoreTable[msg.playerIndex] = msg.newScore;
```

The `playerIndex` originates from the first four bytes of the `packet` parameter (decoded as a `uint32_t` in `decode_score_update()` at line 20). The packet is received from a connected game client over the network and is untrusted.

## Fix

Add a bounds check before writing:

```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // or log an error and return
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The vulnerability exists because `msg.playerIndex` is a `uint32_t` that can hold any value from 0 to 4,294,967,295, yet `scoreTable` is a fixed array with only `MAX_PLAYERS` (16) elements. A malicious or corrupted packet can supply an index far beyond the array bounds, causing a write to arbitrary memory locations.

The fix validates that `playerIndex` falls within the valid range `[0, MAX_PLAYERS)` before using it as an array subscript. The early return discards invalid packets silently; for robustness, a production implementation might log the dropped packet or track it as a protocol violation.
