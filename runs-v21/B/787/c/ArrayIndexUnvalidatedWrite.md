## Verdict

Confirmed. The array index at line 34 is derived from untrusted network data (via `packet` parameter) and is accessed with no bounds check against the destination's actual capacity.

## Source

The vulnerability originates in the `apply_score_update()` function. The `packet` parameter carries untrusted data from a network source. The function decodes this packet in `decode_score_update()`, extracting a `uint32_t playerIndex` field that can hold values from 0 to 4,294,967,295. This index is then used directly to access `scoreTable`, which is a fixed-size array with only 16 elements (capacity: indices 0–15).

## Fix

### File: score_update.c

```c
#include <stdint.h>
#include <string.h>

#define MAX_PLAYERS 16

/* Per-player high score table, indexed by player slot. */
static int scoreTable[MAX_PLAYERS];

/*
 * Wire format for a ScoreUpdate message received from a game client:
 *   bytes 0-3  playerIndex (uint32_t, little-endian)
 *   bytes 4-7  newScore    (int32_t, little-endian)
 */
typedef struct {
    uint32_t playerIndex;
    int32_t newScore;
} ScoreUpdateMsg;

static void decode_score_update(const uint8_t *packet, ScoreUpdateMsg *out) {
    memcpy(&out->playerIndex, packet, sizeof(out->playerIndex));
    memcpy(&out->newScore, packet + sizeof(out->playerIndex), sizeof(out->newScore));
}

/*
 * Applies a score update received from a connected client to the
 * in-memory score table. Called once per ScoreUpdate packet from the
 * network read loop.
 */
void apply_score_update(const uint8_t *packet) {
    ScoreUpdateMsg msg;
    decode_score_update(packet, &msg);

    /* Validate playerIndex before accessing scoreTable to prevent out-of-bounds write */
    if (msg.playerIndex >= MAX_PLAYERS) {
        /* Reject updates with an invalid player index */
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds a bounds check immediately after decoding the network message and before the array write. The condition `if (msg.playerIndex >= MAX_PLAYERS)` validates that the index falls within the valid range [0, MAX_PLAYERS–1] as specified by CWE-787 C guidance: "Valid indices are 0 to size - 1". If the network packet carries an out-of-range index, the function rejects the update by returning early, preventing the out-of-bounds write.

The check follows the prescribed pattern: validate the offset against the destination's actual capacity (16 elements) rather than trusting the value embedded in the untrusted packet. This satisfies the key principle: "Never trust a length or offset taken from user input, a file, or the network; validate it against the actual destination capacity, not the sender's claim."

## Behaviour changes

**No functional changes to valid operations:** Packets with valid player indices (0–15) continue to update the score table as intended. The return type and success path remain identical.

**Out-of-bounds packets are now rejected:** Packets with `playerIndex >= 16` are silently discarded (via early return) instead of corrupting adjacent memory. This is the intended behaviour for a security boundary: invalid input is rejected rather than processed.

**No impact on message encoding or decoding:** The `decode_score_update()` function is unchanged; it continues to parse the wire format exactly as before. Only the unsafe write has been guarded.

**Error signalling trade-off:** The original code had no failure path; the fix silently discards invalid packets. If the caller needs to distinguish between accepted and rejected updates, the function signature would need to change to return a status code—a design decision beyond the scope of the vulnerability fix and left to the application's requirements.
