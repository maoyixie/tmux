#include <stddef.h>
#include <assert.h>
#include <fcntl.h>

#include "tmux.h"

extern void input_parse_buffer(struct window_pane *, u_char *, size_t);

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct window_pane wp;
    memset(&wp, 0, sizeof(struct window_pane));

    u_char *input_data = (u_char *)malloc(Size);
    if (input_data == NULL)
    {
        return 0;
    }

    memcpy(input_data, Data, Size);

    input_parse_buffer(&wp, input_data, Size);

    free(input_data);
    return 0;
}