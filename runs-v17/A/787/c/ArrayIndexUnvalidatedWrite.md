## Verdict
CONFIRMED. Out-of-bounds write at line 34: `msg.playerIndex` used as array index without bounds validation.

## Source
The vulnerability is in the `apply_score_update` function, which receives an untrusted network packet and decodes it into `msg.playerIndex` (a `uint32_t`). This value is then used directly as an array index on line 34 without validation, despite `scoreTable` having only 16 elements. An attacker can craft a packet with any `playerIndex` value to write outside the array bounds.

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

    // Validate playerIndex is within bounds before array access
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation
The fix adds a bounds check before the array write: `if (msg.playerIndex >= MAX_PLAYERS) { return; }`. This ensures that only valid indices [0, MAX_PLAYERS) are used to access the `scoreTable` array. Any packet with an out-of-bounds `playerIndex` is rejected silently, preventing the out-of-bounds write.
