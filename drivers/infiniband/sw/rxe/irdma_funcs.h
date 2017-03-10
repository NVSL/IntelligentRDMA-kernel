#include "irdma.h"

// Functions available to user-defined handle_funcs, to be used in the course of handling an incoming packet.

struct irdma_mem {
  struct rxe_mem* mr;
  u64 va;
  u32 length;  // length in bytes
};

// Gets a new 'resource'
struct resp_res* get_new_resource(struct irdma_context* ic);

// Sends a packet with the specified opcode_num (previously registered with register_opcode)
// E.g. you can use this to send an 'ack' packet in response to received packet
// payload : payload for the packet, can be NULL for no payload
// cur_pkt : current packet, i.e. the one you're responding to (the one passed to your handle_func)
// syndrome, psn : descriptions TBD
int send_packet(
    struct irdma_context* ic,
    unsigned opcode_num,
    struct irdma_mem* payload,
		struct rxe_pkt_info* cur_pkt,
    u8 syndrome,
    u32 psn
);
