#ifndef IRDMA_HELPERS_H
#define IRDMA_HELPERS_H

// Functions that are *private* (not for direct use by users in handlers,
// like those in irdma_funcs.h), but need to be shared between rxe_resp.c
// and irdma_funcs.c.  That is, they're useful for behind-the-scenes
// implementations of the user functions available in irdma_funcs.h, and
// also useful in rxe_resp.c.
// Perhaps in the future we merge rxe_resp.c and irdma_funcs.c.

#include "irdma_funcs.h"

// Process a class A or C error (both are treated the same in this implementation)
void __do_class_ac_error(struct rxe_qp* qp, u8 syndrome, enum ib_wc_status status);

void __cleanup(struct rxe_qp* qp, struct rxe_pkt_info* req_pkt);

struct resp_res* __get_new_resource(struct rxe_qp* qp);

int __send_packet_with_opcode(
    struct rxe_qp* qp,
    struct irdma_mem* payload,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn,
    unsigned opcode_num
);

int __send_packet_raw(
    struct rxe_qp* qp,
    struct rxe_pkt_info* pkt,
    struct sk_buff* skb,
    struct rxe_dev* rxe,
    bool atomicack
);

#endif
