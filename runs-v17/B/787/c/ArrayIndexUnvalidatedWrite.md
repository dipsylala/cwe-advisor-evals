## Verdict

**CWE-787: Out-of-bounds Write**  
**Location:** `evals/cases/787/c/ArrayIndexUnvalidatedWrite/score_update.c`, line 34  
**Status:** Exploitable  
**Confidence:** High

The `scoreTable[msg.playerIndex]` write at line 34 writes to an array indexed by untrusted network data with no bounds validation. An attacker can provide any 32-bit value in the `playerIndex` field to write out of bounds, corrupting adjacent memory or the return address.

## Source

**Data origin:** Network packet received by `apply_score_update()`, untrusted input from remote client.

**Data path:**
1. Untrusted `packet` parameter arrives from network
2. `decode_score_update()` decodes bytes 0-3 as `msg.playerIndex` (uint32_t, little-endian)
3. No validation occurs on the decoded index value
4. `msg.playerIndex` is used directly as an array index at line 34

**Sink:** `scoreTable[msg.playerIndex] = msg.newScore;` at line 34. The array `scoreTable` has fixed size `MAX_PLAYERS` (16 elements). Valid indices are 0–15; any value ≥16 or interpreted as a different sign writes out of bounds.

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

    /* Validate player index is within bounds before writing */
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds a bounds check before the array write: `if (msg.playerIndex >= MAX_PLAYERS) return;`. The untrusted `playerIndex` value decoded from the network packet is compared against the actual array capacity (16). If the index is out of bounds, the function returns early and rejects the write. Valid indices are 0–15; any value ≥16 is silently rejected rather than corrupting adjacent memory. This follows CWE-787 C guidance: "Validate every write's offset and length against the destination's real capacity before the write" and "Valid indices are 0 to size - 1." The check uses unsigned comparison (`>=`) to catch both oversized and negative values (which wrap to large unsigned values when interpreted as uint32_t).

## Behaviour changes

**Return value:** The function now returns early (with no explicit return value; return type is void) if the index is invalid, instead of proceeding to write. Callers do not distinguish between a successful write and a rejected out-of-bounds write, so this graceful rejection prevents corruption without breaking the existing call signature or introducing a new error-reporting path. The original code had no error reporting either.

**Side effect:** Invalid packets no longer modify `scoreTable`. This is the intended behaviour change: reject untrusted indices rather than writing arbitrary memory.

**No other changes:** The wire protocol parsing, the structure of decoded messages, and the function signature remain identical. The fix only adds the missing validation at the critical write point.
