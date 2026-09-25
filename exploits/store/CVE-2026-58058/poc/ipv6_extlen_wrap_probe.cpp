#include <cstdint>
#include <cstdio>
#include <cstring>

using u8 = uint8_t;

static bool is_extension(u8 type) {
  switch (type) {
  case 0:
  case 43:
  case 44:
  case 60:
    return true;
  default:
    return false;
  }
}

static bool is_upper(u8 type) {
  switch (type) {
  case 6:
  case 17:
  case 58:
  case 132:
    return true;
  default:
    return false;
  }
}

static const u8 *parse_ipv6_payload(const u8 *packet, unsigned int *len, u8 *nxt, bool upper_only) {
  const u8 *p;
  const u8 *end;

  if (*len < 40)
    return nullptr;

  p = packet;
  end = p + *len;
  *nxt = packet[6];
  p += 40;

  while (p < end && is_extension(*nxt)) {
    if (p + 2 > end)
      return nullptr;
    *nxt = *p;
    p += (*(p + 1) + 1) * 8;
  }

  *len = end - p;

  if (upper_only && !is_upper(*nxt))
    return nullptr;

  return p;
}

int main() {
  u8 packet[48];
  std::memset(packet, 0, sizeof(packet));

  packet[0] = 0x60;
  packet[4] = 0x00;
  packet[5] = 0x08;
  packet[6] = 0;
  packet[40] = 17;
  packet[41] = 1;

  unsigned int captured_len = sizeof(packet);
  unsigned int payload_len = captured_len;
  u8 next_header = 0;
  const u8 *payload = parse_ipv6_payload(packet, &payload_len, &next_header, true);

  std::printf("helper_returned=%s\n", payload ? "true" : "false");
  std::printf("next_header=%u\n", static_cast<unsigned>(next_header));
  std::printf("payload_offset=%td\n", payload ? payload - packet : -1);
  std::printf("wrapped_payload_len=%u\n", payload_len);

  unsigned int validator_len = captured_len;
  unsigned int ip_payload_len = (static_cast<unsigned>(packet[4]) << 8) | packet[5];
  if (payload_len > ip_payload_len)
    validator_len -= payload_len - ip_payload_len;

  std::printf("validator_len_after_adjust=%u\n", validator_len);
  std::printf("captured_len=%u\n", captured_len);
  return 0;
}
