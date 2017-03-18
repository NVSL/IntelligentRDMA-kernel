#ifndef IRDMA_H
#define IRDMA_H

#include "rxe.h"

void irdma_init(void);

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
  char name[64];
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
// name : a name for this irdma_op (max 63 characters, cannot be "")
// handle_func : a function to be called to handle incoming packets of this type
//   (see also irdma_funcs.h)
// ack : if TRUE, packets of this type will be treated as 'ack' packets
//   better explanation TBD
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if irdma_op_num is outside allowed range or if 'name' is too long
//   OPCODE_IN_USE if the desired irdma_op_num is already in use
register_opcode_status register_irdma_op(
    unsigned irdma_op_num,
    char* name,
    handle_status (*handle_func)(struct irdma_context*, struct rxe_pkt_info*),
    bool ack
);

// opcode_num : the desired opcode number (not already in use)
// name : a name for the opcode (max 63 characters, cannot be "")
// irdma_op_num : the number of the irdma_op for this opcode
//   (previously registered with register_irdma_op)
// qpt : which qp type this opcode is to be used on (e.g. IB_QPT_RC, IB_QPT_UD, etc)
// immdt : whether the packet includes an immediate value to be presented to the receiver
//   'immdt' and 'invalidate' cannot both be TRUE.
// invalidate : whether the packet should (in addition to whatever else it does) 'invalidate'
//   a remote memory region.  'immdt' and 'invalidate' cannot both be TRUE.
// requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
//   If immdt==TRUE, requiresReceive must be TRUE.
//   TODO: also if invalidate==TRUE?
// postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
//   If immdt==TRUE, postComplete must be TRUE.
//   TODO: also if invalidate==TRUE?
// atomicack : set to TRUE iff the packet is an ack/response to an IRDMA_ATOMIC operation
//   (in this case irdma_op_num should have been registered with ack==TRUE)
// sched_priority : to my current understanding, setting this to TRUE instructs the
//   internal scheduler to always handle an incoming packet of this type immediately,
//   pushing aside other tasks (e.g. posting sends, completes, etc).
//   In existing code, only IB_OPCODE_RC_RDMA_READ_REQUEST gets this treatment.
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if opcode_num is outside allowed range, or irdma_op_num has not been registered,
//     or the 'name' string is too long, or if the combination of arguments passed is invalid
//   OPCODE_IN_USE if the desired opcode_num is already in use
register_opcode_status register_single_opcode(
    unsigned opcode_num,
    char* name,
    unsigned irdma_op_num,
    enum ib_qp_type qpt,
    bool immdt, bool invalidate, bool requiresReceive, bool postComplete,
    bool atomicack, bool sched_priority
);

enum ynb { YES, NO, BOTH };

// Sometimes you want to transmit information that is (or may be) too large for a single packet.
// To do this, you need an "opcode series", which has four opcodes, indicating the
// 'start', 'middle', 'end', or 'only' of a series, respectively.
// Then, if you wanted to send a series of 5 packets, you would send them in the order
// 'start', 'middle', 'middle', 'middle', 'end'.
// A series of 3 packets would be 'start', 'middle', 'end'.
// A series of 2 packets would be 'start', 'end' omitting 'middle'.
// Finally, for the instance where all your data fits in a single packet, we have the 'only' packet.
// Arguments:
//   *_opcode_num: the four opcode numbers you wish to register
//   basename: basename for the opcodes; "_start" etc will be appended to form the individual names
//     This means the basename must be max 56 characters, if immdt==NO and invalidate==NO;
//     max 47 characters, if immdt==NO and invalidate==YES/BOTH;
//     or max 45 characters, if immdt==YES/BOTH
//   irdma_op_num: see comments on register_single_opcode.  Will apply to all four opcodes.
//   qpt: see comments on register_single_opcode.  Will apply to all four opcodes.
//   immdt: whether the series includes an immediate value to be presented to the receiver.
//     In any case, only the opcodes which end the series (i.e. 'end' and 'only') carry the immediate.
//     If YES, the 'end' and 'only' opcodes carry an immediate.  If NO, they don't.
//     If BOTH, then two different versions of the 'end' and 'only' opcodes will be registered;
//       versions without an immediate will be registered under end_opcode_num and only_opcode_num,
//       whereas versions with an immediate will be registered under
//       end_opcode_num_immdt and only_opcode_num_immdt.
//     See also below, 'immdt--invalidate restriction'
//   end_opcode_num_immdt: see comments on 'immdt' above; only used if immdt==BOTH, else ignored
//   only_opcode_num_immdt: see comments on 'immdt' above; only used if immdt==BOTH, else ignored
//   invalidate : whether the packet should (in addition to whatever else it does) 'invalidate'
//     a remote memory region.
//     In any case, only the opcodes which end the series (i.e. 'end' and 'only') carry the invalidate.
//     If YES, the 'end' and 'only' opcodes carry an invalidate.  If NO, they don't.
//     If BOTH, then two different versions of the 'end' and 'only' opcodes will be registered;
//     versions without an invalidate will be registered under end_opcode_num and only_opcode_num,
//     whereas versions with an invalidate will be registered under
//     end_opcode_num_inv and only_opcode_num_inv.
//     See also below, 'immdt-invalidate restriction'
//   end_opcode_num_inv: see comments on 'invalidate' above; only used if invalidate==BOTH, else ignored
//   only_opcode_num_inv: see comments on 'invalidate' above; only used if invalidate==BOTH, else ignored
//   requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
//     The 'receive' WQE will be required for opcodes which start the series (i.e. 'start' and 'only').
//     If requiresReceive==FALSE but the series carries an immediate, a 'receive' WQE will still be required,
//     but in this case for the opcodes which end the series (i.e. 'end' and 'only').
//     TODO: Unclear if we should handle requiresReceive==FALSE + invalidate similarly?
//       No examples of that case in the existing opcodes
//       Provisionally, I'm letting the requiresReceive==FALSE hold even for series carrying invalidates
//   postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
//     The 'cqe' will be posted with the opcodes which end the series (i.e. 'end' and 'only').
//     If immdt==YES, postComplete must be TRUE.  If immdt==BOTH, the value of this argument applies for
//     the non-immediate version of the series; the immediate version will implicitly have postComplete==TRUE
//     TODO: Unclear if we should handle invalidate==YES or invalidate==BOTH similarly?
//       No examples of postComplete==FALSE + invalidate==YES/BOTH in the existing opcodes
//       Provisionally, I'm treating invalidate==YES/BOTH like immdt==YES/BOTH for postComplete
//   atomicack : set to TRUE iff the series is an ack/response to an IRDMA_ATOMIC operation
//     (in this case irdma_op_num should have been registered with ack==TRUE)
//   sched_priority : to my current understanding, setting this to TRUE instructs the
//     internal scheduler to always handle incoming packets from this series immediately,
//     pushing aside other tasks (e.g. posting sends, completes, etc).
//     In existing code, no series gets this treatment (only the single opcode IB_OPCODE_RC_RDMA_READ_REQUEST).
// immdt-invalidate restriction:
//   If either 'immdt' or 'invalidate' is YES, the other must be NO.
//   If both 'immdt' and 'invalidate' are BOTH, a total of three versions of the series will be registered:
//     one carrying neither immediate nor invalidate (registered under end_opcode_num and only_opcode_num)
//     one carrying just an immediate (registered under end_opcode_num_immdt and only_opcode_num_immdt)
//     one carrying just an invalidate (registered under end_opcode_num_inv and only_opcode_num_inv)
//   In particular, no series may carry both an immediate and an invalidate.
// returns:
//   OPCODE_OK on success
//   OPCODE_INVALID if any of the opcode_nums are outside allowed range, or irdma_op_num has not been 
//     registered, or the 'basename' string is too long, or if the combination of arguments passed is invalid
//     In this case there is no guarantee given as to which of the series opcodes may or may not have
//     been successfully registered; the only guarantee is that the state remains consistent
//     i.e. each opcode is either fully registered or fully not.
//   OPCODE_IN_USE if any of the opcode_nums were already in use
//     In this case, all the requested opcode_nums which were not already in use are guaranteed to be
//     properly registered before this function returns.
register_opcode_status register_opcode_series(
    unsigned start_opcode_num,
    unsigned middle_opcode_num,
    unsigned end_opcode_num,
    unsigned only_opcode_num,
    char* basename,
    unsigned irdma_op_num,
    enum ib_qp_type qpt,
    enum ynb immdt, unsigned end_opcode_num_immdt, unsigned only_opcode_num_immdt,
    enum ynb invalidate, unsigned end_opcode_num_inv, unsigned only_opcode_num_inv,
    bool requiresReceive, bool postComplete, bool atomicack, bool sched_priority
);

#endif
