## Verdict

VULNERABLE. The array index `msg.playerIndex` is untrusted network input with no bounds validation before the write on line 34.

## Source

Line 29-31: The `apply_score_update()` function receives a packet pointer from the network. The `decode_score_update()` function extracts `playerIndex` and `newScore` from the packet data via memcpy without any validation.

The `playerIndex` value (line 20) is copied directly from the untrusted packet into `msg.playerIndex` as a `uint32_t` with no range checking.

## Fix

Add a bounds check before writing to the array. Insert the validation immediately after decoding:

```c
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    // Validate the player index is within the scoreTable bounds
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Reject out-of-bounds index
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

The check `msg.playerIndex >= MAX_PLAYERS` ensures the index falls within the valid range [0, MAX_PLAYERS-1] for the 16-element array. Any packet with playerIndex >= 16 is rejected and processing stops.

## Explanation

The vulnerability occurs because `msg.playerIndex` is an untrusted value from network input but is used directly as an array index without validation. The C language does not perform bounds checking on array access, so an attacker can craft a packet with a large playerIndex value to write to memory outside the allocated scoreTable buffer, corrupting adjacent data.

The fix validates the index against the array's actual capacity (16 elements) before performing the write. This follows the CWE-787/C guidance: "Valid indices are 0 to size - 1" and "Validate offset <= buf_len first". The check rejects any index >= MAX_PLAYERS, preventing the out-of-bounds write.

## Behaviour changes

- Packets with playerIndex values >= 16 are now rejected silently (the function returns early without modifying scoreTable).
- Packets with valid playerIndex values (0-15) behave identically to the unfixed code: the score is updated normally.
- An attacker can no longer corrupt memory by sending a packet with an oversized playerIndex.
