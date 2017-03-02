#include "irdma.h"

register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    enum rxe_hdr_mask mask
) {
  if(opcode_num >= RXE_NUM_OPCODE) return INVALID;
  if(rxe_opcode[opcode_num].name) return IN_USE;  // assume that name==NULL indicates free
    // TODO: should make sure that rxe_opcode is initialized s.t. this is the case
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
  return OK;
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

