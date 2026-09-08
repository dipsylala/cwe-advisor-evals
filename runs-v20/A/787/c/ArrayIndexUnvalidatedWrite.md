## Verdict

Confirmed. `apply_score_update` writes to `scoreTable[msg.playerIndex]` using a `playerIndex` value decoded directly from an attacker-controlled network packet, with no bounds check against the table's size. A client that sends a `playerIndex` of 16 or greater (up to the full `uint32_t` range) causes an out-of-bounds write to `scoreTable`, corrupting adjacent static memory with an attacker-chosen 32-bit value (`newScore`).

## Source

`packet`, the raw `ScoreUpdate` message bytes passed into `apply_score_update`, is received from a connected game client over the network (per the function's own doc comment: "Called once per ScoreUpdate packet from the network read loop"). `decode_score_update` copies bytes 0-3 of that untrusted buffer verbatim into `msg.playerIndex` with no range restriction, so `msg.playerIndex` carries the full, attacker-controlled `uint32_t` range (0 to 4294967295) into `apply_score_update`.

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

    if (msg.playerIndex >= MAX_PLAYERS) {
        /* Reject: playerIndex from the wire is attacker-controlled and
         * out of range for scoreTable. Drop the update rather than
         * writing out of bounds. */
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

`scoreTable` has exactly `MAX_PLAYERS` (16) `int` slots, and array indexing in C performs no automatic bounds checking - the compiler emits a direct address computation (`&scoreTable[0] + msg.playerIndex * sizeof(int)`) and writes there unconditionally. `msg.playerIndex` is a `uint32_t` decoded straight from network bytes the client supplies, so nothing upstream constrains it to `0..15`.

The fix adds an explicit range check, rejecting the update when `msg.playerIndex >= MAX_PLAYERS`, before the array write. Because `playerIndex` is unsigned, a single `>=` comparison against the upper bound is sufficient - there is no negative case to also guard against, unlike a signed index. This is a bounds check on a value the function itself defines the valid domain for (a slot index into its own fixed-size table), not a format-guessing allowlist, so it does not risk rejecting otherwise-legitimate input.

Placing the check immediately after decoding and before the write ensures the out-of-bounds write can never execute for a malicious or malformed packet; in-range updates (`playerIndex` 0-15) are applied exactly as before, so legitimate client behavior is unaffected.
