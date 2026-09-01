#include <string.h>
#include <stdlib.h>

int feature_flag_enabled(void) {
    const char *mode = getenv("FEATURE_MODE");
    if (strcmp(mode, "strict") == 0) {
        return 1;
    }

    return 0;
}
