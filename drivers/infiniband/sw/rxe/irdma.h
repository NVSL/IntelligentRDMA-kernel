#ifndef IRDMA_H
#define IRDMA_H

#include "rxe.h"

// handle_status is the return type of the handle_func for an irdma_op.
typedef enum {
  OK = 0,  // indicates no error
  ERROR_LENGTH,  // indicates that copy_data returned -ENOSPC
  ERROR_MALFORMED_WQE,  // indicates that copy_data returned any nonzero code other than -ENOSPC
  ERROR_RKEY_VIOLATION,  // explanation TBD, but name seems straightforward
  ERROR_RNR,  // 'receiver not ready' - indicates that a required receive request was not posted
  ERROR_MISALIGNED_ATOMIC,  // indicates that the target address for an atomic operation wasn't 8-bytes aligned
  DONE,  // indicates we are completely done handling the packet, with no error.
         // Note that OK should usually be used instead - with OK, a bunch of bookkeeping is done to
         // complete the processing of this packet and prepare for the next.
         // DONE indicates that you've already done all this yourself.
} handle_status;

// an irdma_context (along with info about the received packet) is passed to the handle_func for an irdma_op
struct irdma_context {
  struct rxe_qp* qp;
};

// irdma_op arises out of the observation that all the existing entries in
// rxe_opcode have, in their 'mask' field, exactly one of the following 5 bits set:
// RXE_ACK_MASK, RXE_SEND_MASK, RXE_WRITE_MASK, RXE_READ_MASK, RXE_ATOMIC_MASK
// We separate this distinction out into an 'irdma_op' separate from the mask,
// and allow its extensibility
// We also observe that RXE_REQ_MASK is set iff RXE_ACK_MASK is not,
// and we generalize references to RXE_REQ_MASK to mean (not ack)
// 'ack'==TRUE indicates 'ack'-type irdma_ops (ones that would have RXE_ACK_MASK set)
#define IRDMA_MAX_OPS 256
struct irdma_op {
  char* name;
  handle_status (*handle_func)(struct irdma_context*, struct rxe_pkt_info*);
  bool ack;
};
extern struct irdma_op irdma_op[IRDMA_MAX_OPS];
// cheating for now, allow other code to test against IRDMA_* opnums.
// The reason I don't like this is that this prohibits new opnums from emulating
// the same functionality as (wherever the test is happening).
#ifndef IRDMA_OPNUMS
#define IRDMA_OPNUMS
#define IRDMA_ACK 0
#define IRDMA_SEND 1
#define IRDMA_WRITE 2
#define IRDMA_READ 3
#define IRDMA_ATOMIC 4
#endif

typedef enum { OPCODE_OK, OPCODE_INVALID, OPCODE_IN_USE } register_opcode_status;

// irdma_op_num : the desired irdma_op_num (not already in use)
// name : a name for this irdma_op
// handle_func : a function to be called to handle incoming packets of this type
//   (see also irdma_funcs.h)
// ack : if TRUE, packets of this type will be treated as 'ack' packets
//   better explanation TBD
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if irdma_op_num is outside allowed range
//   OPCODE_IN_USE if the desired irdma_op_num is already in use
register_opcode_status register_irdma_op(
    unsigned irdma_op_num,
    char* name,
    handle_status (*handle_func)(struct irdma_context*, struct rxe_pkt_info*),
    bool ack
);

// opcode_num : the desired opcode number (not already in use)
// name : a name for the opcode
// irdma_op_num : the number of the irdma_op for this opcode
//   (previously registered with register_irdma_op)
// qpt : which qp type this opcode is to be used on (e.g. IB_QPT_RC, IB_QPT_UD, etc)
// immdt : whether the packet includes an immediate value to be presented to the receiver
// payload : whether the packet contains a payload
// invalidate : whether the packet involves an 'invalidate' (better explanation TBD)
// requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
// postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
// start, middle, end : whether the packet is the first, middle, or last of a series
//   if the packet is the only in a series, then under some circumstances you should set
//   both 'start' and 'end' (but not 'middle').  Better explanation TBD
// atomicack : set to TRUE iff the packet is an ack/response to an IRDMA_ATOMIC operation
//   (in this case irdma_op_num should have been registered with ack==TRUE)
// sched_priority : to my current understanding, setting this to TRUE instructs the
//   internal scheduler to always handle an incoming packet of this type immediately,
//   pushing aside other tasks (e.g. posting sends, completes, etc).
//   In existing code, only IB_OPCODE_RC_RDMA_READ_REQUEST gets this treatment.
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if opcode_num is outside allowed range, or irdma_op_num has not been registered,
//     or if the combination of arguments passed is invalid
//   OPCODE_IN_USE if the desired opcode_num is already in use
register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    unsigned irdma_op_num,
    enum ib_qp_type qpt,
    bool immdt, bool payload, bool invalidate, bool requiresReceive, bool postComplete,
    bool start, bool middle, bool end, bool atomicack, bool sched_priority
);

#endif
