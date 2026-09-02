#include <cstdint>
#include <cstring>

// Reassembles a fragmented message from a custom binary transport protocol.
// Each fragment carries its own header and payload; headerLen and payloadLen
// are parsed directly from the fragment's wire header fields, which the
// remote peer controls.
uint8_t* ReassembleFragment(const uint8_t* headerData, uint32_t headerLen,
                             const uint8_t* payloadData, uint32_t payloadLen)
{
    // Both lengths are attacker-influenced 32-bit fields taken straight off
    // the wire, so their sum can wrap around before it is ever validated.
    // A large-enough pair (e.g. headerLen = 0xFFFFFFF0, payloadLen = 0x20)
    // wraps totalSize down to 0x10, far smaller than either input.
    uint32_t totalSize = headerLen + payloadLen;

    // SAST FINDING: CWE-787 (Out-of-bounds Write) reported here. Sink is the next statement.
    uint8_t* buffer = new uint8_t[totalSize];

    std::memcpy(buffer, headerData, headerLen);
    std::memcpy(buffer + headerLen, payloadData, payloadLen);

    return buffer;
}
