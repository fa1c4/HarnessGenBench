#ifndef HGB_SAMPLE_H
#define HGB_SAMPLE_H
#include <stddef.h>
#include <stdint.h>
int hgb_parse_record(const uint8_t *data, size_t size);
uint32_t hgb_record_checksum(const uint8_t *data, size_t size);
#endif
