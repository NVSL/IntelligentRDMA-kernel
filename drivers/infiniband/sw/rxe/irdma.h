#include <rdma/ib_pack.h>  // BIT(), maybe among other things
#include "rxe_opcode.h"
#include "rxe_hdr.h"

typedef enum { OK, ERROR } status;

// irdma_op arises out of the observation that all the existing entries in
// rxe_opcode have, in their 'mask' field, exactly one of the following 5 bits set:
// RXE_ACK_MASK, RXE_SEND_MASK, RXE_WRITE_MASK, RXE_READ_MASK, RXE_ATOMIC_MASK
// We separate this distinction out into an 'irdma_op' separate from the mask,
// and allow its extensibility
// We also observe that RXE_REQ_MASK is set iff RXE_ACK_MASK is not,
// and we generalize references to RXE_REQ_MASK to mean (not irdma_op IRDMA_ACK)
#define IRDMA_MAX_OPS 256
struct irdma_op {
  char* name;
  status (*handle_func)(struct rxe_qp, struct rxe_pkt_info);
};
extern struct irdma_op irdma_op[IRDMA_MAX_OPS];
// 'built-in' (pre-existing) irdma_op_nums
#define IRDMA_ACK 0
#define IRDMA_SEND 1
#define IRDMA_WRITE 2
#define IRDMA_READ 3
#define IRDMA_ATOMIC 4

typedef enum { OPCODE_OK, OPCODE_INVALID, OPCODE_IN_USE } register_opcode_status;

// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if irdma_op_num is outside allowed range
//   OPCODE_IN_USE if the desired irdma_op_num is already in use
register_opcode_status register_irdma_op(
    unsigned irdma_op_num,
    char* name,
    status (*handle_func)(struct rxe_qp, struct rxe_pkt_info)
);

// opcode_num : the desired opcode number (not already in use)
// name : a name for the opcode
// irdma_op_num : the number of the irdma_op for this opcode
//   (previously registered with register_irdma_op)
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if opcode_num is outside allowed range
//   OPCODE_IN_USE if the desired opcode_num is already in use
register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    unsigned irdma_op_num
);

// returns a bitwise-OR of the appropriate flags defined in rxe_hdr_mask
// irdma_op_num : the number of the irdma_op for this opcode
//   (previously registered with register_irdma_op)
// immdt : whether the packet includes an immediate value to be presented to the receiver
// payload : whether the packet contains a payload
// invalidate : whether the packet involves an 'invalidate' (better explanation TBD)
// requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
// postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
// start, middle, end : whether the packet is the first, middle, or last of a series
//   if the packet is the only in a series, then under some circumstances you should set
//   both 'start' and 'end' (but not 'middle').  Better explanation TBD
// atomicack : set to TRUE iff the packet is an ack/response to an IRDMA_ATOMIC operation
//   (in this case irdma_op_num should always be IRDMA_ACK)
enum rxe_hdr_mask computeMask(struct rxe_qp* qp, unsigned irdma_op_num, bool immdt,
    bool payload, bool invalidate, bool requiresReceive, bool postComplete,
    bool start, bool middle, bool end, bool atomicack);

// requires that the 'mask' field of info already be populated and valid
void computeOffset(struct rxe_opcode_info* info);
