#ifndef IRDMA_FUNCS_H
#define IRDMA_FUNCS_H

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

// Gets an existing 'resource' by psn, or NULL if not found
struct resp_res* get_existing_resource(struct irdma_context* ic, u32 psn);

// Sends an 'ack' packet or series in response to received 'req' packet
// payload : payload for the packet or series, can be NULL for no payload
// req_pkt : the 'req' packet you're responding to (the one passed to your handle_func)
// syndrome, psn : descriptions TBD
int send_ack_packet_or_series(
    struct irdma_context* ic,
    struct irdma_mem* payload,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn
);

// Sends a 'nak' packet in response to received 'req' packet
// this generally indicates some kind of error processing the 'req' packet
// req_pkt : the 'req' packet you're responding to (the one passed to your handle_func)
// syndrome, psn : descriptions TBD
int send_nak_packet(
    struct irdma_context* ic,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn
);

// This function assumes that everything is already initialized and ready to go
// (otherwise use the functions above)
int resend_packet(
    struct irdma_context* ic,
    struct rxe_pkt_info* pkt,
    struct sk_buff* skb,
    struct rxe_dev* rxe,
    bool atomicack
);

// Process a class A or C error (both are treated the same in this implementation)
void do_class_ac_error(struct irdma_context* ic, u8 syndrome, enum ib_wc_status status);

#endif
