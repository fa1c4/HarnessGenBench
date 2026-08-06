#include <stdint.h>
#include <stddef.h>
#include "sample.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return hgb_sample_api(data, size);
}
