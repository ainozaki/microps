#include "icmp.h"

#include <stddef.h>

#include "ip.h"
#include "util.h"

#define ICMP_TYPE_ECHOREPLY      0x00
#define ICMP_TYPE_DEST_UNREACH   0x03
#define ICMP_TYPE_SOURCE_QUENCH  0x04
#define ICMP_TYPE_REDIRECT       0x5
#define ICMP_TYPE_ECHO           0x08
#define ICMP_TYPE_TIME_EXCEEDED  0x0b
#define ICMP_TYPE_PARAM_PROBLEM  0x0c
#define ICMP_TYPE_TIMESTAMP      0x0d
#define ICMP_TYPE_TIMESTAMPREPLY 0x0e
#define ICMP_TYPE_INFO_REQUEST   0x0f
#define ICMP_TYPE_INFO_REPLY     0x10

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint32_t value;
};

struct icmp_echo {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint16_t id;
  uint16_t seq;
};

static char* icmp_type_ntoa(uint8_t type) {
  switch (type) {
    case ICMP_TYPE_ECHOREPLY:
      return "EchoReply";
    case ICMP_TYPE_DEST_UNREACH:
      return "DestinationUnreachable";
    case ICMP_TYPE_SOURCE_QUENCH:
      return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
      return "Redirect";
    case ICMP_TYPE_ECHO:
      return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
      return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
      return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
      return "Timestamp";
    case ICMP_TYPE_TIMESTAMPREPLY:
      return "TimestampReply";
    case ICMP_TYPE_INFO_REQUEST:
      return "InformationRequest";
    case ICMP_TYPE_INFO_REPLY:
      return "InformationReply";
  }
  return "Unknown";
}

static void icmp_dump(const uint8_t* data, size_t len) {
  struct icmp_hdr* hdr;
  struct icmp_echo* echo;

  flockfile(stderr);
  hdr = (struct icmp_hdr*)data;
  fprintf(stderr, "       type: %u (%s)\n", hdr->type,
          icmp_type_ntoa(hdr->type));
  fprintf(stderr, "       code: %u\n", hdr->code);
  fprintf(stderr, "        sum: 0x%04x\n", ntoh32(hdr->sum));
  switch (hdr->type) {
    case ICMP_TYPE_ECHOREPLY:
    case ICMP_TYPE_ECHO:
      echo = (struct icmp_echo*)hdr;
      fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
      fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
      break;
    default:
      fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->value));
      break;
  }
  funlockfile(stderr);
}

void icmp_input(const uint8_t* data,
                size_t len,
                ip_addr_t src,
                ip_addr_t dst,
                struct ip_iface* iface) {
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)),
         ip_addr_ntop(src, addr2, sizeof(addr2)), len);
  icmp_dump(data, len);
}

int icmp_init() {
  if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) < 0) {
    errorf("ICMP ip_protocol_register() failed");
  }
  return 0;
}
