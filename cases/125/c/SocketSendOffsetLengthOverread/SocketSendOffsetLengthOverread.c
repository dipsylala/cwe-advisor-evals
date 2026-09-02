#include <stddef.h>
#include <sys/types.h>

extern ssize_t socket_send(const void *buf, size_t len);

ssize_t send_response_slice(const unsigned char *buffer, size_t buffer_len, size_t offset, size_t length)
{
    if (offset > buffer_len) {
        return -1;
    }

    // SAST FINDING: CWE-125 (Out-of-bounds Read) reported here. Sink is the next statement.
    return socket_send(buffer + offset, length);
}
