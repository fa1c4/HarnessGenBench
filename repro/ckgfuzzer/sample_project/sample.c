#include "sample.h"
uint32_t hgb_record_checksum(const uint8_t *data, size_t size) {
  uint32_t acc = 2166136261u;
  if (!data) return 0;
  for (size_t i = 0; i < size; ++i) { acc ^= data[i]; acc *= 16777619u; }
  return acc;
}
int hgb_parse_record(const uint8_t *data, size_t size) {
  if (!data || size < 4) return 0;
  if (data[0] != 'H' || data[1] != 'G' || data[2] != 'B') return 0;
  uint8_t declared = data[3];
  if ((size_t)declared > size - 4) return -1;
  return (int)(hgb_record_checksum(data + 4, declared) & 0x7fffffffU);
}
