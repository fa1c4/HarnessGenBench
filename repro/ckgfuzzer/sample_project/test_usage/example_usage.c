#include "../sample.h"
#include <stdint.h>
int main(void) {
  const uint8_t data[] = {'H', 'G', 'B', 3, 'o', 'k', '!'};
  return hgb_parse_record(data, sizeof(data)) < 0;
}
