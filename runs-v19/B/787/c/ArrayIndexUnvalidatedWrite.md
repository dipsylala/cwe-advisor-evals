## Verdict

Exploitable. The untrusted `playerIndex` field from a network packet is used directly as an array index without bounds validation, permitting an out-of-bounds write to `scoreTable`.

## Source

The `playerIndex` field arrives from the network as the first 4 bytes of an untrusted wire-format packet. It is extracted into `msg.playerIndex` (a `uint32_t`) at line 20-21 via `decode_score_update()`, which reads from the caller-supplied `packet` buffer using `memcpy()`.

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

    // Validate playerIndex is within bounds before array write
    if (msg.playerIndex >= MAX_PLAYERS) {
        // Reject invalid player index - out of range
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds a bounds validation check before the array indexing at line 34. The untrusted `playerIndex` field (a `uint32_t` from the network) is compared against `MAX_PLAYERS` (16), and the function returns early if the index is out of range. This ensures only valid indices [0, 15] proceed to the array write, eliminating the out-of-bounds write vulnerability. The check follows the C language guidance principle: "Valid indices are 0 to size - 1" and validates the index against the destination's actual capacity before the write.

## Behaviour changes

None. The fix rejects invalid input (out-of-bounds indices) and preserves the original behavior for valid indices. The early return when the index is invalid prevents the write and has no other side effects—no return value changes, no altered arguments, no implicit state modifications. Valid player updates (indices 0-15) proceed unchanged.
