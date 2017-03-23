#include "irdma.h"

// forward declarations of structs etc we use
struct rxe_pkt_info;
struct rxe_dev;
struct rxe_mem;

// Functions available to user-defined handle_funcs, to be used in the course of handling an incoming packet.

struct irdma_mem {
  struct rxe_mem* mr;
  u64 va;
  u32 length;  // length in bytes
};

// Gets a new 'resource'
struct resp_res* get_new_resource(struct irdma_context* ic);
// Gets an existing 'resource' by psn, or NULL if not found
struct resp_res* get_existing_resource(struct irdma_context* ic, u32 psn);

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

// This function assumes that everything is already initialized and ready to go
// It can be used to resend packets (and it's also used internally by send_packet() above)
int send_packet_raw(
    struct irdma_context* ic,
    struct rxe_pkt_info* pkt,
    struct sk_buff* skb,
    struct rxe_dev* rxe,
    bool atomicack
);

// Process a class A or C error (both are treated the same in this implementation)
void do_class_ac_error(struct irdma_context* ic, u8 syndrome, enum ib_wc_status status);
