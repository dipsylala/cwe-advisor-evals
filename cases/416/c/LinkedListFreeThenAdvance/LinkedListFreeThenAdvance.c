#include <stdlib.h>

struct SessionNode {
    int session_id;
    int expired;
    struct SessionNode *next;
};

void refresh_session(int session_id);

void purge_expired_sessions(struct SessionNode *head) {
    struct SessionNode *node = head;
    while (node != NULL) {
        if (node->expired) {
            free(node);
            node = node->next;
            continue;
        }

        refresh_session(node->session_id);
        node = node->next;
    }
}
