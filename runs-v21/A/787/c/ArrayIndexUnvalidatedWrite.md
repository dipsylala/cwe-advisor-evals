## Verdict

CONFIRMED. The array indexing at line 34 uses `msg.playerIndex` without bounds validation. Since `playerIndex` is decoded from untrusted network data as a `uint32_t` and the array `scoreTable` has only 16 elements, any value >= 16 causes an out-of-bounds write.

## Source

File: `score_update.c`, line 34

The vulnerable code path:
1. `apply_score_update()` receives untrusted packet data
2. `decode_score_update()` extracts `playerIndex` (uint32_t) from the packet without validation
3. Line 34 writes directly to `scoreTable[msg.playerIndex]` without checking bounds

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

    // Validate playerIndex is within bounds before accessing array
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;  // Discard invalid packet
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds an explicit bounds check before the array write. If `playerIndex` is outside the valid range [0, MAX_PLAYERS), the function returns without modifying the array, discarding the malicious or malformed packet. This is the appropriate policy for untrusted network input: reject values that do not conform to the expected format or constraints, rather than attempting to correct them.

The check `msg.playerIndex >= MAX_PLAYERS` covers all invalid indices, since `MAX_PLAYERS` is 16 and valid indices are 0–15. The condition is evaluated before the array access, preventing any out-of-bounds write.
