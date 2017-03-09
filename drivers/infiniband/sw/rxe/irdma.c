#include "irdma.h"

struct irdma_op irdma_op[] = {
  [IRDMA_ACK] = { .name = "IRDMA_ACK", .handle_func = &handle_ack },
  [IRDMA_SEND] = { .name = "IRDMA_SEND", .handle_func = &handle_send },
  [IRDMA_WRITE] = { .name = "IRDMA_WRITE", .handle_func = &handle_write },
  [IRDMA_READ] = { .name = "IRDMA_READ", .handle_func = &handle_read },
  [IRDMA_ATOMIC] = { .name = "IRDMA_ATOMIC", .handle_func = &handle_atomic },
};

register_opcode_status register_irdma_op(
    unsigned irdma_op_num,
    char* name,
    status (*handle_func)(struct rxe_qp, struct rxe_pkt_info)
) {
  if(irdma_op_num >= IRDMA_MAX_OPS) return OPCODE_INVALID;
  if(irdma_op[irdma_op_num].name) return OPCODE_IN_USE;  // assume that name==NULL indicates free
    // TODO: should make sure that irdma_op is initialized s.t. this is the case
  irdma_op[irdma_op_num] = { .name = name, .handle_func = handle_func };
  return OPCODE_OK;
}

register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    unsigned irdma_op_num
) {
  if(opcode_num >= RXE_NUM_OPCODE) return OPCODE_INVALID;
  if(rxe_opcode[opcode_num].name) return OPCODE_IN_USE;  // assume that name==NULL indicates free
    // TODO: should make sure that rxe_opcode is initialized s.t. this is the case
  enum rxe_hdr_mask mask = computeMask(irdma_op_num);
  rxe_opcode[opcode_num] = {
    .name   = name,
    .mask   = mask,
    .length = RXE_BTH_BYTES
      + (mask & RXE_IMMDT_MASK  ? RXE_IMMDT_BYTES  : 0)
      + (mask & RXE_RETH_MASK   ? RXE_RETH_BYTES   : 0)
      + (mask & RXE_AETH_MASK   ? RXE_AETH_BYTES   : 0)
      + (mask & RXE_ATMACK_MASK ? RXE_ATMACK_BYTES : 0)
      + (mask & RXE_ATMETH_MASK ? RXE_ATMETH_BYTES : 0)
      + (mask & RXE_IETH_MASK   ? RXE_IETH_BYTES   : 0)
      + (mask & RXE_RDETH_MASK  ? RXE_RDETH_BYTES  : 0)
      + (mask & RXE_DETH_MASK   ? RXE_DETH_BYTES   : 0)
      ,
  };
  computeOffset(&rxe_opcode[opcode_num]);
  return OPCODE_OK;
}

enum rxe_hdr_mask computeMask(struct rxe_qp* qp, unsigned irdma_op_num, bool immdt, 
    bool payload, bool invalidate, bool requiresReceive, bool postComplete, 
    bool start, bool middle, bool end, bool atomicack) {
  if(unlikely(atomicack && irdma_op_num != IRDMA_ACK)) {
    pr_err("IRDMA: Tried to register opcode with atomicack but not IRDMA_ACK");
  }
#define SET_IF(cond, set_what) \
  ( (cond) ? (set_what) : (! (set_what) ) )
  return
        // RXE_LRH_MASK and RXE_BTH_MASK are not set by any existing opcodes.
      SET_IF(false, RXE_LRH_MASK)
    | SET_IF(false, RXE_BTH_MASK)
        // RXE_GRH_MASK and RXE_LOOPBACK_MASK are never set by existing opcodes; instead,
        // it looks like they are set automatically under the appropriate circumstances.
    | SET_IF(false, RXE_GRH_MASK)
    | SET_IF(false, RXE_LOOPBACK_MASK)
        // These mask bits must (currently) be indicated by the user; more explanation in irdma.h
    | SET_IF(immdt, RXE_IMMDT_MASK)
    | SET_IF(payload, RXE_PAYLOAD_MASK)
    | SET_IF(invalidate, RXE_IETH_MASK)
    | SET_IF(requiresReceive, RXE_RWR_MASK)
    | SET_IF(postComplete, RXE_COMP_MASK)
    | SET_IF(start, RXE_START_MASK)
    | SET_IF(middle, RXE_MIDDLE_MASK)
    | SET_IF(end, RXE_END_MASK)
        // RXE_RETH_MASK indicates whether the packet needs an 'RDMA extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF((irdma_op_num == IRDMA_READ || irdma_op_num == IRDMA_WRITE) && start, RXE_RETH_MASK)
        // RXE_AETH_MASK indicates whether the packet needs an 'ack extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF(irdma_op_num == IRDMA_ACK && !middle, RXE_AETH_MASK)
        // RXE_ATMETH_MASK indicates whether the packet needs an 'atomic extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF(irdma_op_num == IRDMA_ATOMIC, RXE_ATMETH_MASK)
        // RXE_ATMACK_MASK indicates whether the packet needs an 'atomic ack extended transport header',
        // i.e. is an ack/response to an IRDMA_ATOMIC operation.  For now we let the user indicate this.
    | SET_IF(atomicack, RXE_ATMACK_MASK)
        // RXE_RDETH_MASK indicates whether the packet needs a 'reliable datagram extended transport header'.
    | SET_IF(qp_type(qp) == IB_QPT_RD, RXE_RDETH_MASK)
        // RXE_DETH_MASK indicates whether the packet needs a 'datagram extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF((qp_type(qp) == IB_QPT_RD || qp_type(qp) == IB_QPT_UD) && irdma_op_num != IRDMA_ACK, RXE_DETH_MASK)
    ;
}

void computeOffset(struct rxe_opcode_info* info) {
  unsigned runningOffset = 0;
  if(true) {
    info->offset[RXE_BTH] = runningOffset;
    runningOffset += RXE_BTH_BYTES;
  }
#define INCLUDE_OFFSET(hdrType)            \
  if(info->mask & (hdrType ## _MASK)) {    \
    info->offset[hdrType] = runningOffset; \
    runningOffset += (hdrType ## _BYTES);  \
  }
  // comments indicate known ordering constraints from existing opcodes.
  // Existing opcodes under-specify the ordering
  //   (for instance, another valid ordering has IMMDT right before PAYLOAD).
  // Taken for granted is that BTH is first and PAYLOAD is last.
  // This is simply one valid ordering for existing opcodes.
  INCLUDE_OFFSET(RXE_RDETH)  // before DETH and AETH
  INCLUDE_OFFSET(RXE_DETH)  // before RETH and ATMETH
  INCLUDE_OFFSET(RXE_RETH)  // before IMMDT
  INCLUDE_OFFSET(RXE_IMMDT)
  INCLUDE_OFFSET(RXE_AETH)  // before ATMACK
  INCLUDE_OFFSET(RXE_ATMACK)
  INCLUDE_OFFSET(RXE_ATMETH)
  INCLUDE_OFFSET(RXE_IETH)
  if(info->mask & RXE_PAYLOAD_MASK) {
    info->offset[RXE_PAYLOAD] = runningOffset;
    // don't adjust runningOffset - we don't need to (we're done)
    //   and furthermore we can't (don't know payload length)
  }
}

