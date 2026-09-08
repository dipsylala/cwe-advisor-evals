## Verdict

Exploitable. CWE-787 (Out-of-bounds Write), confirmed. `apply_score_update()` in `score_update.c` writes to `scoreTable[msg.playerIndex]` at line 34 using a `playerIndex` decoded directly from an attacker-supplied network packet, with no check against the table's bound (`MAX_PLAYERS`, 16 entries). A client sending a `playerIndex` of 16 or higher, or a very large `uint32_t` value, causes `scoreTable[msg.playerIndex] = msg.newScore;` to write an attacker-controlled 32-bit value at an attacker-controlled offset outside the `scoreTable` array - a write-what-where primitive against adjacent static storage.

## Source

`packet`, the raw byte buffer passed into `apply_score_update()` from the network read loop (per the function's own doc comment: "Called once per ScoreUpdate packet from the network read loop"). `decode_score_update()` copies the first 4 bytes of `packet` verbatim into `msg.playerIndex` (line 20, `memcpy(&out->playerIndex, packet, sizeof(out->playerIndex))`) with no validation - the field is under full control of whoever sent the packet.

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

    /* playerIndex is decoded straight from the network packet: it is a
     * claim from the sender, not a guarantee about the table's size.
     * Reject anything outside scoreTable's allocated bounds before it is
     * used to index the array. playerIndex is unsigned, so this single
     * check also covers the low end. */
    if (msg.playerIndex >= MAX_PLAYERS) {
        return;
    }

    scoreTable[msg.playerIndex] = msg.newScore;
}
```

## Explanation

The fix adds a bounds check - `msg.playerIndex >= MAX_PLAYERS` - between decoding the packet and indexing `scoreTable`, and returns without writing when the index falls outside the table's allocated 16 entries. `playerIndex` is a `uint32_t`, so the single upper-bound comparison also covers the entire non-negative range; there is no negative-index case to separately guard against. The comparison uses the same `MAX_PLAYERS` constant the array is declared with, so the check tracks the destination's actual capacity rather than any value the sender supplies, closing the out-of-bounds write while leaving valid updates (indices 0-15) untouched.

## Behaviour changes

- Added an early `return` when `playerIndex >= MAX_PLAYERS`. Previously such a packet corrupted memory adjacent to `scoreTable`; now the update for that packet is silently dropped and the function returns without effect. `apply_score_update()` was and remains `void`, so this preserves its existing signature and calling convention - the caller (the network read loop) receives no new indication of rejection, matching the original code's lack of any error-reporting path for this function.
- No other differences: `decode_score_update()`, the wire format, and the valid-index write path (`scoreTable[msg.playerIndex] = msg.newScore;`) are unchanged.

Verification: no C compiler (gcc/clang/cl) was reachable in this environment, so the fix was checked by hand instead of with a compiler. The only new token introduced is a comparison against `MAX_PLAYERS`, a macro already defined and used earlier in the same file for the array's own declaration; `msg.playerIndex` is a field already read at line 20 with matching type (`uint32_t`); no new symbols, includes, calls, or signature changes were introduced, and the fix's braces and control flow were traced by hand to confirm they close correctly within the existing function body.
