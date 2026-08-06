#include "sample.h"
int hgb_sample_api(const uint8_t *data, size_t size) {
    if (!data || size < 1) return 0;
    return (int)data[0];
}
