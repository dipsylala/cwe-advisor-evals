#include <stddef.h>
#include <string.h>

int copy_packet_window(const unsigned char *packet,
                       size_t packet_len,
                       int offset,
                       size_t length,
                       unsigned char *out,
                       size_t out_capacity)
{
    if ((size_t)offset + length <= packet_len && length <= out_capacity) {
        // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
        memcpy(out, packet + offset, length);
        return (int)length;
    }

    return -1;
}
