#include <rdma/ib_pack.h>  // BIT(), maybe among other things
#include "rxe_opcode.h"
#include "rxe_hdr.h"

typedef enum { OK, INVALID, IN_USE } register_opcode_status;

// opcode_num : the desired opcode number (not already in use)
// name : a name for the opcode
// mask : bitwise-OR of any of the following flags (defined in rxe_hdr_mask)
//   Available flags: (with descriptions of what they do, as reflected by my current knowledge of the system)
//   RXE_LRH_MASK    : Not used in any existing opcodes
//   RXE_GRH_MASK    : Existing opcodes never set this; looks like it is set automatically under the appropriate circumstances
//   RXE_BTH_MASK    : Not used in any existing opcodes
//   RXE_IMMDT_MASK  : packet includes an immediate value to be presented to the receiver
//   RXE_RETH_MASK   : packet needs an 'RDMA extended transport header'.
//                     For existing opcodes, this is set iff (RXE_READ_MASK or RXE_WRITE_MASK) and (RXE_START_MASK)
//   RXE_AETH_MASK   : packet needs an 'ack extended transport header'.
//                     For existing opcodes, this is set on all RXE_ACK_MASK packets except those with RXE_MIDDLE_MASK.
//   RXE_ATMETH_MASK : packet needs an 'atomic extended transport header'.
//                     For existing opcodes, this is set iff RXE_ATOMIC_MASK is
//   RXE_ATMACK_MASK : packet needs an 'atomic ack extended transport header'; i.e. is an ack/response to an atomic operation
//   RXE_IETH_MASK   : operation involves an 'invalidate'
//   RXE_RDETH_MASK  : packet needs a 'reliable datagram extended transport header'; i.e. this is an RD operation
//   RXE_DETH_MASK   : packet needs a 'datagram extended transport header'.
//                     For existing opcodes, this is set for all RD and UD operations except ones with RXE_ACK_MASK
//   RXE_PAYLOAD_MASK : packet contains a payload
//   RXE_REQ_MASK    : operation 'is a request'
//                     Existing opcodes all have either RXE_REQ_MASK or RXE_ACK_MASK set, but never both
//   RXE_ACK_MASK    : operation is an ack/response.
//                     Although it is sometimes set and sometimes not, existing code appears never to check this bit
//   RXE_SEND_MASK   : operation is a form of RDMA Send
//   RXE_WRITE_MASK  : operation is a form of RDMA Write
//   RXE_READ_MASK   : operation is a form of RDMA Read
//   RXE_ATOMIC_MASK : operation is an RDMA atomic op
//   RXE_RWR_MASK    : operation requires that the receiver has posted a 'receive' WQE
//   RXE_COMP_MASK   : a 'cqe' should be posted to the completion queue upon operation completion
//   RXE_START_MASK  : packet is the first (or only) of a series
//   RXE_MIDDLE_MASK : packet is in the middle of a series
//   RXE_END_MASK    : packet is the last (or only) of a series
//   RXE_LOOPBACK_MASK : Existing opcodes never set this; looks like it is set automatically under the appropriate circumstances
// returns :
//   OK on success
//   INVALID if opcode_num is outside allowed range
//   IN_USE if the desired opcode_num is already in use
register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    enum rxe_hdr_mask mask
);

void computeOffset(struct rxe_opcode_info* info);
