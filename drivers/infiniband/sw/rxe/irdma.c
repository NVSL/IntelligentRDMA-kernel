#include "irdma.h"
#include <linux/string.h>

struct irdma_op irdma_op[IRDMA_MAX_OPS];

void irdma_init(void) {
  unsigned i;
  for(i = 0; i < IRDMA_MAX_OPS; i++) {
    irdma_op[i].name[0] = '\0';  // mark as free
  }
  for(i = 0; i < RXE_NUM_OPCODE; i++) {
    rxe_opcode[i].name[0] = '\0';  // mark as free
  }
}

register_opcode_status register_irdma_op(
    unsigned irdma_op_num,
    char* name,
    handle_status (*handle_func)(struct irdma_context*, struct rxe_pkt_info*),
    bool ack
) {
  if(irdma_op_num >= IRDMA_MAX_OPS) return OPCODE_INVALID;
  if(strlen(name) > 63) return OPCODE_INVALID;
  if(!name[0]) return OPCODE_INVALID;
  if(irdma_op[irdma_op_num].name[0]) return OPCODE_IN_USE;  // name=="" indicates free
  strcpy(irdma_op[irdma_op_num].name, name);
  irdma_op[irdma_op_num].handle_func = handle_func;
  irdma_op[irdma_op_num].ack = ack;
  return OPCODE_OK;
}

// requires that the 'mask' field of info already be populated and valid
static void computeOffset(struct rxe_opcode_info* info) {
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
  info->offset[RXE_PAYLOAD] = runningOffset;  // regardless of whether packet is expected to have payload
  // don't adjust runningOffset - we don't need to (we're done)
  //   and furthermore we can't (don't know payload length)
}

// internal register_opcode function, used by the public-facing 'register_single_opcode' and
//   'register_opcode_series'
static register_opcode_status __register_opcode(
    unsigned opcode_num,
    char* name,
    unsigned irdma_op_num,
    enum ib_qp_type qpt,
    bool immdt, bool invalidate, bool requiresReceive, bool postComplete,
    bool atomicack, bool sched_priority,
    /* internal arguments */ bool start, bool middle, bool end
) {
  enum rxe_hdr_mask mask;
  if(unlikely(opcode_num >= RXE_NUM_OPCODE)) return OPCODE_INVALID;
  if(unlikely(!name[0])) return OPCODE_INVALID;
  if(unlikely(rxe_opcode[opcode_num].name[0])) return OPCODE_IN_USE;  // name=="" indicates free
  if(unlikely(!irdma_op[irdma_op_num].name[0])) return OPCODE_INVALID;
  if(unlikely(atomicack && !irdma_op[irdma_op_num].ack)) return OPCODE_INVALID;
  if(unlikely(immdt && invalidate)) return OPCODE_INVALID;
    // although conceptually there's no problem with immdt && invalidate (as far as I know), it can't
    // be allowed in the existing implementation due to, e.g., the definition of the ib_wc struct
  if(unlikely(immdt && !requiresReceive)) return OPCODE_INVALID;
  if(unlikely(immdt && !postComplete)) return OPCODE_INVALID;
  if(unlikely(strlen(name) > 63)) return OPCODE_INVALID;
#define SET_IF(cond, set_what) \
  ( (cond) ? (set_what) : 0 )
  mask = 
        // RXE_LRH_MASK and RXE_BTH_MASK are not set by any existing opcodes.
      SET_IF(false, RXE_LRH_MASK)
    | SET_IF(false, RXE_BTH_MASK)
        // RXE_GRH_MASK and RXE_LOOPBACK_MASK are never set by existing opcodes; instead,
        // it looks like they are set automatically under the appropriate circumstances.
    | SET_IF(false, RXE_GRH_MASK)
    | SET_IF(false, RXE_LOOPBACK_MASK)
        // These mask bits must (currently) be indicated by the user; more explanation in irdma.h
    | SET_IF(immdt, RXE_IMMDT_MASK)
    // | SET_IF(payload, RXE_PAYLOAD_MASK)  // appears to never be used for anything in existing code
        // RXE_PAYLOAD_MASK was set for all opcodes in a series, plus the UD_SEND_ONLY opcodes,
        // and not for any other opcodes.
    | SET_IF(invalidate, RXE_IETH_MASK)
    | SET_IF(requiresReceive, RXE_RWR_MASK)
    | SET_IF(postComplete, RXE_COMP_MASK)
    | SET_IF(start, RXE_START_MASK)
    | SET_IF(middle, RXE_MIDDLE_MASK)
    | SET_IF(end, RXE_END_MASK)
    | SET_IF(sched_priority, IRDMA_SCHED_PRIORITY_MASK)
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
        // Strangely, this bit is never used for anything (as far as I can tell), and "RD" is not a 
        // valid qp_type.  So until I learn otherwise, I'm just going to leave this unset for all opcodes.
        // (in the existing code, it is set for all opcodes with name "IB_OPCODE_RD_*")
    | SET_IF(false /*qpt == IB_QPT_RD*/, RXE_RDETH_MASK)
        // RXE_DETH_MASK indicates whether the packet needs a 'datagram extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF((false /*qpt == IB_QPT_RD*/ || qpt == IB_QPT_UD) && irdma_op_num != IRDMA_ACK, RXE_DETH_MASK)
        // Invented this solely so that one can distinguish 'ack' packets from non-ack,
        // in a flexible way that allows multiple (custom) irdma_ops to be 'ack's.
        // However, for now we just set it for IRDMA_ACK packets
  ;
  strcpy(rxe_opcode[opcode_num].name, name);
  rxe_opcode[opcode_num].mask = mask;
  rxe_opcode[opcode_num].irdma_op_num = irdma_op_num;
  rxe_opcode[opcode_num].qpt = qpt;
  rxe_opcode[opcode_num].length = RXE_BTH_BYTES
      + (mask & RXE_IMMDT_MASK  ? RXE_IMMDT_BYTES  : 0)
      + (mask & RXE_RETH_MASK   ? RXE_RETH_BYTES   : 0)
      + (mask & RXE_AETH_MASK   ? RXE_AETH_BYTES   : 0)
      + (mask & RXE_ATMACK_MASK ? RXE_ATMACK_BYTES : 0)
      + (mask & RXE_ATMETH_MASK ? RXE_ATMETH_BYTES : 0)
      + (mask & RXE_IETH_MASK   ? RXE_IETH_BYTES   : 0)
      + (mask & RXE_RDETH_MASK  ? RXE_RDETH_BYTES  : 0)
      + (mask & RXE_DETH_MASK   ? RXE_DETH_BYTES   : 0)
  ;
  computeOffset(&rxe_opcode[opcode_num]);
  return OPCODE_OK;
}

register_opcode_status register_single_opcode(
  unsigned opcode_num,
  char* name,
  unsigned irdma_op_num,
  enum ib_qp_type qpt,
  bool immdt, bool invalidate, bool requiresReceive, bool postComplete,
  bool atomicack, bool sched_priority
) {
  return __register_opcode(
      opcode_num,
      name,
      irdma_op_num,
      qpt,
      immdt, invalidate, requiresReceive, postComplete,
      atomicack, sched_priority,
      /* start    = */ true,   /* \                           */
      /* middle   = */ false,  /*  |--  (treat as an 'only')  */
      /* end      = */ true    /* /                           */
      );
}

// Set a to the 'min', where the order is OPCODE_INVALID < OPCODE_IN_USE < OPCODE_OK
static void compound(register_opcode_status* a, register_opcode_status b) {
  if(*a==OPCODE_INVALID) return;
  if(b==OPCODE_OK) return;
  if(*a==OPCODE_OK) {*a = b; return;}
  if(b==OPCODE_INVALID) {*a = b; return;}
  return;  // both are OPCODE_IN_USE
}

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
) {
  register_opcode_status ret = OPCODE_OK;
  size_t len = strlen(basename);
  char startname[64], middlename[64], endname[64], onlyname[64];
  char endname_immdt[64], onlyname_immdt[64], endname_inv[64], onlyname_inv[64];
  if(unlikely(len > 56 || len == 0)) return OPCODE_INVALID;
  if(unlikely(invalidate!=NO && len > 47)) return OPCODE_INVALID;
  if(unlikely(immdt!=NO && len > 45)) return OPCODE_INVALID;
  if(unlikely(immdt==YES && invalidate!=NO)) return OPCODE_INVALID;
  if(unlikely(invalidate==YES && immdt!=NO)) return OPCODE_INVALID;
  if(unlikely(immdt==YES && !postComplete)) return OPCODE_INVALID;
  if(unlikely(invalidate==YES && !postComplete)) return OPCODE_INVALID;
  strcpy(startname, basename);
  strcpy(middlename, basename);
  strcpy(endname, basename);
  strcpy(onlyname, basename);
  if(immdt==YES) {
    strcat(endname, "_with_immdt");  // throughout, one tiny way we're altering the functionality of the
    strcat(onlyname, "_with_immdt"); // existing code is that these constructed names will be slightly
                                     // different than the names that were previously used
  } else if(immdt==BOTH) {
    strcpy(endname_immdt, basename);
    strcpy(onlyname_immdt, basename);
    strcat(endname_immdt, "_with_immdt");
    strcat(onlyname_immdt, "_with_immdt");
  }
  if(invalidate==YES) {
    strcat(endname, "_with_inv");
    strcat(onlyname, "_with_inv");
  } else if(invalidate==BOTH) {
    strcpy(endname_inv, basename);
    strcpy(onlyname_inv, basename);
    strcat(endname_inv, "_with_inv");
    strcat(onlyname_inv, "_with_inv");
  }
  compound(&ret, __register_opcode(
      start_opcode_num, startname, irdma_op_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ requiresReceive,
      /* postComplete    = */ false,
      atomicack, sched_priority,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ false
      ));
  if(ret==OPCODE_INVALID) return ret;
  compound(&ret, __register_opcode(
      middle_opcode_num, middlename, irdma_op_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ false,
      /* postComplete    = */ false,
      atomicack, sched_priority,
      /* start           = */ false,
      /* middle          = */ true,
      /* end             = */ false
      ));
  if(ret==OPCODE_INVALID) return ret;
  compound(&ret, __register_opcode(
      end_opcode_num, endname, irdma_op_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ (immdt==YES),
      /* postComplete    = */ postComplete,
      atomicack, sched_priority,
      /* start           = */ false,
      /* middle          = */ false,
      /* end             = */ true
      ));
  if(ret==OPCODE_INVALID) return ret;
  compound(&ret, __register_opcode(
      only_opcode_num, onlyname, irdma_op_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ requiresReceive || (immdt==YES),
      /* postComplete    = */ postComplete,
      atomicack, sched_priority,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ true
      ));
  if(ret==OPCODE_INVALID) return ret;
  if(immdt==BOTH) {
    compound(&ret, __register_opcode(
        end_opcode_num_immdt, endname_immdt, irdma_op_num, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ !requiresReceive,
        /* postComplete    = */ true,
        atomicack, sched_priority,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true
      ));
    if(ret==OPCODE_INVALID) return ret;
    compound(&ret, __register_opcode(
        only_opcode_num_immdt, onlyname_immdt, irdma_op_num, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ true,
        /* postComplete    = */ true,
        atomicack, sched_priority,
        /* start           = */ true,
        /* middle          = */ false,
        /* end             = */ true
        ));
    if(ret==OPCODE_INVALID) return ret;
  }
  if(invalidate==BOTH) {
    compound(&ret, __register_opcode(
        end_opcode_num_inv, endname_inv, irdma_op_num, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ false,
        /* postComplete    = */ true,
        atomicack, sched_priority,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true
        ));
    if(ret==OPCODE_INVALID) return ret;
    compound(&ret, __register_opcode(
        only_opcode_num_inv, onlyname_inv, irdma_op_num, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ requiresReceive,
        /* postComplete    = */ true,
        atomicack, sched_priority,
        /* start           = */ true,  // the (one) existing ONLY_WITH_INVALIDATE opcode has 'false' here,
                                       // but I'm assuming that's an error/typo
        /* middle          = */ false,
        /* end             = */ true
        ));
    if(ret==OPCODE_INVALID) return ret;
  }
  return ret;
}
