#include "irdma.h"
#include "rxe_hdr.h"
#include <linux/string.h>

struct rxe_wr_opcode_info rxe_wr_opcode_info[IRDMA_MAX_WR_OPCODES];
struct rxe_opcode_info rxe_opcode[IRDMA_MAX_RXE_OPCODES];

unsigned series_id(struct rxe_opcode_group* opcode_group) {
  if(opcode_group->is_series) return opcode_group->opcode_set.start_opcode_num;
  else return opcode_group->opcode_num;
}

bool is_registered(struct rxe_opcode_group* opcode_group) {
  return series_id(opcode_group)!=0;  // series_id coincides with our convention for
                                      // marking things registered
}

register_opcode_status register_std_wr_opcode(
    unsigned wr_opcode_num,
    char* name,
    enum ib_qp_type* qpts,
    unsigned num_qpts,
    enum rxe_wr_mask type,
    bool immdt,
    bool invalidate,
    bool wr_inline,
    bool alwaysEnableSolicited,
    enum ib_wc_opcode sender_wc_opcode,
    bool postComplete, enum ib_wc_opcode receiver_wc_opcode,
    unsigned ack_opcode_num
) {
  unsigned i;
  struct rxe_wr_opcode_info *info = &rxe_wr_opcode_info[wr_opcode_num];
  struct rxe_opcode_info ack_opcode_info = rxe_opcode[ack_opcode_num];
  if(wr_opcode_num >= IRDMA_MAX_WR_OPCODES) return OPCODE_NUM_OUTSIDE_RANGE;
  if(strlen(name) > 63) return NAME_INVALID;
  if(!name[0]) return NAME_INVALID;
  if(info->name[0]) return OPCODE_IN_USE;  // name=="" indicates free
  if(type & ~(WR_SEND_MASK | WR_WRITE_MASK | WR_READ_MASK | WR_ATOMIC_MASK)) return ARGUMENTS_INVALID;
    // the above line enforces that you can only send one of those four bits
    // (or combinations of, I guess) as 'type'
  if(immdt && !postComplete) return ARGUMENTS_INVALID;
  if(invalidate && !postComplete) return ARGUMENTS_INVALID;
  if(!ack_opcode_info.name[0]) return OPCODE_REG_ERROR;
  if(!ack_opcode_info.is_ack) return OPCODE_REG_ERROR;
  if(unlikely(immdt && invalidate)) return ARGUMENTS_INVALID;
    // although conceptually there's no problem with immdt && invalidate (as far as I know), it
    // can't be allowed in the existing implementation due to, e.g., the definition of the ib_wc
    // or rxe_send_wr structs (probably among other things)
  strcpy(info->name, name);
  info->type = STANDARD;
  for(i = 0; i < WR_MAX_QPT; i++) {
    // mark opcode group not-yet-registered for each qpt
    // strictly speaking this is probably not great practice (accessing both parts of a union
    //   and assuming the second assignment won't override the first), but since these are
    //   unsigned ints and the value is 0, I know it will work
    //   Following this, checking either opcode_set.start_opcode_num, or opcode_num, will give 0
    info->std.opcode_groups[i].opcode_set.start_opcode_num = 0;
    info->std.opcode_groups[i].opcode_num = 0;
  }
  info->mask =
      (wr_inline ? WR_INLINE_MASK : 0)
    | (immdt ? WR_IMMDT_MASK : 0)
    | (invalidate ? WR_INV_MASK : 0)
    | (postComplete ? WR_COMP_MASK : 0)
    | (alwaysEnableSolicited ? WR_SOLICITED_MASK : 0)
    | type;
  for(i = 0; i < WR_MAX_QPT; i++) info->std.qpts[i] = false;
  for(i = 0; i < num_qpts; i++) info->std.qpts[qpts[i]] = true;
  info->std.sender_wc_opcode = sender_wc_opcode;
  info->std.receiver_wc_opcode = receiver_wc_opcode;
  info->std.ack_opcode_group = rxe_opcode[ack_opcode_num].containingGroup;
  return OPCODE_OK;
}

register_opcode_status register_loc_wr_opcode(
    unsigned wr_opcode_num,
    char* name,
    handle_loc_status (*handle_wr)(struct irdma_context*, struct rxe_send_wqe*),
    bool wr_inline
) {
  struct rxe_wr_opcode_info *info = &rxe_wr_opcode_info[wr_opcode_num];
  if(wr_opcode_num >= IRDMA_MAX_WR_OPCODES) return OPCODE_NUM_OUTSIDE_RANGE;
  if(strlen(name) > 63) return NAME_INVALID;
  if(!name[0]) return NAME_INVALID;
  if(info->name[0]) return OPCODE_IN_USE;  // name=="" indicates free
  strcpy(info->name, name);
  info->type = LOCAL;
  info->mask = (wr_inline ? WR_INLINE_MASK : 0);
  return OPCODE_OK;
}

// requires that the 'mask' field of info already be populated and valid
static void computeLengthAndOffset(struct rxe_opcode_info* info) {
  enum rxe_hdr_mask mask = info->mask;
  unsigned runningOffset = 0;
  info->length = RXE_BTH_BYTES
      + (mask & RXE_IMMDT_MASK  ? RXE_IMMDT_BYTES  : 0)
      + (mask & RXE_RETH_MASK   ? RXE_RETH_BYTES   : 0)
      + (mask & RXE_AETH_MASK   ? RXE_AETH_BYTES   : 0)
      + (mask & RXE_ATMACK_MASK ? RXE_ATMACK_BYTES : 0)
      + (mask & RXE_ATMETH_MASK ? RXE_ATMETH_BYTES : 0)
      + (mask & RXE_IETH_MASK   ? RXE_IETH_BYTES   : 0)
      + (mask & RXE_RDETH_MASK  ? RXE_RDETH_BYTES  : 0)
      + (mask & RXE_DETH_MASK   ? RXE_DETH_BYTES   : 0)
  ;
  if(true) {
    info->offset[RXE_BTH] = runningOffset;
    runningOffset += RXE_BTH_BYTES;
  }
#define INCLUDE_OFFSET(hdrType)            \
  if(mask & (hdrType ## _MASK)) {    \
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

// internal function, used by the public-facing 'register_single_req_opcode' and
//   'register_req_opcode_series'
static register_opcode_status __register_req_opcode(
    unsigned opcode_num,
    char* name,
    IRDMA_REQ_OPNUM irdma_req_opnum,
    handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
    handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
    unsigned wr_opcode_num,
    enum ib_qp_type qpt,
    bool immdt, bool invalidate,
    bool requiresReceive, bool postComplete, unsigned char perms, bool sched_priority, bool comp_swap,
    /* internal arguments */ bool start, bool middle, bool end
) {
  enum rxe_hdr_mask mask;
  struct rxe_opcode_info *info = &rxe_opcode[opcode_num];
  if(unlikely(opcode_num >= IRDMA_MAX_RXE_OPCODES)) return OPCODE_NUM_OUTSIDE_RANGE;
  if(unlikely(opcode_num == 0)) return OPCODE_NUM_OUTSIDE_RANGE;
  if(unlikely(!name[0])) return NAME_INVALID;
  if(unlikely(info->name[0])) return OPCODE_IN_USE;  // name=="" indicates free
  if(unlikely(immdt && invalidate)) return ARGUMENTS_INVALID;
    // although conceptually there's no problem with immdt && invalidate (as far as I know), it can't
    // be allowed in the existing implementation due to, e.g., the definition of the ib_wc struct
  if(unlikely(immdt && !requiresReceive)) return ARGUMENTS_INVALID;
  if(unlikely(immdt && !postComplete)) return ARGUMENTS_INVALID;
  if(unlikely(invalidate && !postComplete)) return ARGUMENTS_INVALID;
  if(unlikely(strlen(name) > 63)) return NAME_INVALID;
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
    | SET_IF(invalidate, RXE_IETH_MASK)
    | SET_IF(requiresReceive, RXE_RWR_MASK)
    | SET_IF(postComplete, RXE_COMP_MASK)
    | SET_IF(start, RXE_START_MASK)
    | SET_IF(middle, RXE_MIDDLE_MASK)
    | SET_IF(end, RXE_END_MASK)
    | SET_IF(sched_priority, IRDMA_SCHED_PRIORITY_MASK)
    | SET_IF(comp_swap, IRDMA_COMPSWAP_MASK)
        // RXE_RETH_MASK indicates whether the packet needs an 'RDMA extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF((irdma_req_opnum == IRDMA_REQ_READ || irdma_req_opnum == IRDMA_REQ_WRITE) && start, RXE_RETH_MASK)
        // RXE_AETH_MASK indicates whether the packet needs an 'ack extended transport header'.
        // This is not the case for any 'request' packets.
    | SET_IF(false, RXE_AETH_MASK)
        // RXE_ATMETH_MASK indicates whether the packet needs an 'atomic extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF(irdma_req_opnum == IRDMA_REQ_ATOMIC, RXE_ATMETH_MASK)
        // RXE_ATMACK_MASK indicates whether the packet needs an 'atomic ack extended transport header',
        // i.e. is an ack/response to an IRDMA_REQ_ATOMIC operation.  Not the case for any 'request' packets.
    | SET_IF(false, RXE_ATMACK_MASK)
        // RXE_RDETH_MASK indicates whether the packet needs a 'reliable datagram extended transport header'.
        // Strangely, this bit is never used for anything (as far as I can tell), and "RD" is not a
        // valid qp_type.  So until I learn otherwise, I'm just going to leave this unset for all opcodes.
        // (in the existing code, it is set for all opcodes with name "IB_OPCODE_RD_*")
    | SET_IF(false /*qpt == IB_QPT_RD*/, RXE_RDETH_MASK)
        // RXE_DETH_MASK indicates whether the packet needs a 'datagram extended transport header'.
        // The rule here reflects existing convention.
    | SET_IF((false /*qpt == IB_QPT_RD*/ || qpt == IB_QPT_UD), RXE_DETH_MASK)
        // RXE_PAYLOAD_MASK was originally set for all writes/sends + read responses.
        // However, it wasn't used for anything in the original code.
        // So I renamed it IRDMA_PAYLOAD_MASK and decided it should only apply to 'req' opcodes
        // (unless I find a good reason to make it also apply to read responses again)
    | SET_IF(irdma_req_opnum == IRDMA_REQ_SEND || irdma_req_opnum == IRDMA_REQ_WRITE, IRDMA_PAYLOAD_MASK)
        // I invented IRDMA_RES_MASK to indicate which packets need "responder resources" available
        // on the receive side.  The rule here reflects existing convention.
    | SET_IF(irdma_req_opnum == IRDMA_REQ_READ || irdma_req_opnum == IRDMA_REQ_ATOMIC, IRDMA_RES_MASK)
  ;
  strcpy(info->name, name);
  info->mask = mask;
  info->is_ack = false;
  info->req.wr_opcode_num = wr_opcode_num;
  info->req.handle_incoming = handle_incoming;
  info->req.handle_duplicate = handle_duplicate;
  info->req.perms = perms;
  info->qpt = qpt;
  computeLengthAndOffset(info);
  return OPCODE_OK;
}

// internal function, used by the public-facing 'register_single_ack_opcode' and
//   'register_ack_opcode_series'
static register_opcode_status __register_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack,
    /* internal arguments */ bool start, bool middle, bool end
) {
  enum rxe_hdr_mask mask;
  struct rxe_opcode_info *info = &rxe_opcode[opcode_num];
  if(unlikely(opcode_num >= IRDMA_MAX_RXE_OPCODES)) return OPCODE_NUM_OUTSIDE_RANGE;
  if(unlikely(opcode_num == 0)) return OPCODE_NUM_OUTSIDE_RANGE;
  if(unlikely(!name[0])) return NAME_INVALID;
  if(unlikely(info->name[0])) return OPCODE_IN_USE;  // name=="" indicates free
  if(unlikely(strlen(name) > 63)) return NAME_INVALID;
  mask =
    // see comments on __register_req_opcode for fuller explanation of mask bits
      SET_IF(start, RXE_START_MASK)
    | SET_IF(middle, RXE_MIDDLE_MASK)
    | SET_IF(end, RXE_END_MASK)
        // The rule here for RXE_AETH_MASK reflects existing convention for 'ack' opcodes
    | SET_IF(!middle, RXE_AETH_MASK)
        // For now we let the user specify rather directly whether RXE_ATMACK_MASK is needed
    | SET_IF(atomicack, RXE_ATMACK_MASK)
  ;
  strcpy(info->name, name);
  info->mask = mask;
  info->is_ack = true;
  info->ack.handle_incoming = handle_incoming;
  info->qpt = IB_QPT_RC;  // all 'ack' opcodes are RC-only
  computeLengthAndOffset(info);
  return OPCODE_OK;
}

static void __deregister_opcode(unsigned opcode_num) {
  rxe_opcode[opcode_num].name[0] = '\0';
}

register_opcode_status register_single_req_opcode(
  unsigned opcode_num,
  char* name,
  IRDMA_REQ_OPNUM irdma_req_opnum,
  handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
  handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
  unsigned wr_opcode_num,
  enum ib_qp_type qpt,
  bool requiresReceive, unsigned char perms, bool sched_priority, bool comp_swap
) {
  register_opcode_status st;
  struct rxe_opcode_group thisGroup;
  struct rxe_wr_opcode_info *wr_info = &rxe_wr_opcode_info[wr_opcode_num];
  if(unlikely(!wr_info->name[0])) return OPCODE_REG_ERROR;
  if(unlikely(wr_info->type==LOCAL)) return OPCODE_REG_ERROR;
  if(unlikely(!wr_info->std.qpts[qpt])) return OPCODE_REG_ERROR;
    // More elegant would be, don't make the user declare supported qpts when registering wr_opcode,
    //   and instead just assume that qpts with registered opcodes are supported, and without are not
    //   However, the existing code marks some wr_opcodes as compatible with IB_QPT_SMI and IB_QPT_GSI,
    //   and others not; and doesn't register opcodes for SMI or GSI.  So we kind of have to keep this,
    //   just to preserve that information?  I wish I understood more about SMI / GSI and why they
    //   don't have opcodes (in rxe_opcode.c in the existing code).
  if(unlikely(is_registered(&wr_info->std.opcode_groups[qpt]))) return OPCODE_IN_USE;
  st = __register_req_opcode(
      opcode_num,
      name,
      irdma_req_opnum,
      handle_incoming,
      handle_duplicate,
      wr_opcode_num,
      qpt,
      /* immdt      = */ wr_info->mask & WR_IMMDT_MASK,
      /* invalidate = */ wr_info->mask & WR_INV_MASK,
      requiresReceive,
      /* postComplete */ wr_info->mask & WR_COMP_MASK,
      perms, sched_priority, comp_swap,
      /* start     = */ true,   /* \                           */
      /* middle    = */ false,  /*  |--  (treat as an 'only')  */
      /* end       = */ true    /* /                           */
      );
  if(st == OPCODE_OK) {
    // don't do these steps if the rxe_opcode registration failed
    // (following the principle of leave-everything-alone-if-error)
    thisGroup.is_series = false;
    thisGroup.opcode_num = opcode_num;
    wr_info->std.opcode_groups[qpt] = thisGroup;
    rxe_opcode[opcode_num].containingGroup = thisGroup;
  }
  return st;
}

register_opcode_status register_single_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
) {
  register_opcode_status st = __register_ack_opcode(
      opcode_num,
      name,
      handle_incoming,
      atomicack,
      /* start     = */ true,   /* \                           */
      /* middle    = */ false,  /*  |--  (treat as an 'only')  */
      /* end       = */ true    /* /                           */
      );
  if(st == OPCODE_OK) {
    // don't do this if the rxe_opcode registration failed
    // (following the principle of leave-everything-alone-if-error)
    struct rxe_opcode_group* thisGroup = &rxe_opcode[opcode_num].containingGroup;
    thisGroup->is_series = false;
    thisGroup->opcode_num = opcode_num;
  }
  return st;
}

#define WITH_CHECK(expr, label) \
  ret = expr; \
  if(ret) { \
    pr_err("Error %d with command " #expr "\n", ret); \
    goto label; \
  }

register_opcode_status register_req_opcode_series(
  unsigned start_opcode_num,
  unsigned middle_opcode_num,
  unsigned end_opcode_num,
  unsigned only_opcode_num,
  char* basename,
  IRDMA_REQ_OPNUM irdma_req_opnum,
  handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
  handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
  unsigned wr_opcode_num,
  enum ib_qp_type qpt,
  enum ynb immdt, unsigned end_opcode_num_immdt, unsigned only_opcode_num_immdt, unsigned wr_opcode_num_immdt,
  enum ynb invalidate, unsigned end_opcode_num_inv, unsigned only_opcode_num_inv, unsigned wr_opcode_num_inv,
  bool requiresReceive, unsigned char perms, bool sched_priority, bool comp_swap
) {
  register_opcode_status ret = OPCODE_OK;
  struct rxe_wr_opcode_info *wr_info = &rxe_wr_opcode_info[wr_opcode_num];
  struct rxe_wr_opcode_info *wr_info_immdt = &rxe_wr_opcode_info[wr_opcode_num_immdt];
  struct rxe_wr_opcode_info *wr_info_inv = &rxe_wr_opcode_info[wr_opcode_num_inv];
  struct rxe_opcode_group* opcode_group = &wr_info->std.opcode_groups[qpt];
  struct rxe_opcode_group* opcode_group_immdt = &wr_info_immdt->std.opcode_groups[qpt];
  struct rxe_opcode_group* opcode_group_inv = &wr_info_inv->std.opcode_groups[qpt];
  size_t len = strlen(basename);
  char startname[64], middlename[64], endname[64], onlyname[64];
  char endname_immdt[64], onlyname_immdt[64], endname_inv[64], onlyname_inv[64];
  if(unlikely(len > 56 || len == 0)) return NAME_INVALID;
  if(unlikely(invalidate!=NO && len > 47)) return NAME_INVALID;
  if(unlikely(immdt!=NO && len > 45)) return NAME_INVALID;
  if(unlikely(immdt==YES && invalidate!=NO)) return ARGUMENTS_INVALID;
  if(unlikely(invalidate==YES && immdt!=NO)) return ARGUMENTS_INVALID;
  if(unlikely(!wr_info->name[0])) return OPCODE_REG_ERROR;
  if(unlikely(wr_info->type==LOCAL)) return OPCODE_REG_ERROR;
  if(unlikely(!wr_info->std.qpts[qpt])) return OPCODE_REG_ERROR;
  if(unlikely(is_registered(opcode_group))) return OPCODE_IN_USE;
  if(unlikely((wr_info->mask & WR_IMMDT_MASK) && immdt!=YES)) return ARGUMENTS_INVALID;
  if(unlikely((wr_info->mask & WR_INV_MASK) && invalidate!=YES)) return ARGUMENTS_INVALID;
  if(unlikely((!(wr_info->mask & WR_IMMDT_MASK)) && immdt==YES)) return ARGUMENTS_INVALID;
  if(unlikely((!(wr_info->mask & WR_INV_MASK)) && invalidate==YES)) return ARGUMENTS_INVALID;
  if(immdt==BOTH) {
    if(unlikely(!wr_info_immdt->name[0])) return OPCODE_REG_ERROR;
    if(unlikely(wr_info_immdt->type==LOCAL)) return OPCODE_REG_ERROR;
    if(unlikely(!wr_info_immdt->std.qpts[qpt])) return OPCODE_REG_ERROR;
    if(unlikely(is_registered(opcode_group_immdt))) return OPCODE_IN_USE;
    if(unlikely(!(wr_info_immdt->mask & WR_IMMDT_MASK))) return ARGUMENTS_INVALID;
  }
  if(invalidate==BOTH) {
    if(unlikely(!wr_info_inv->name[0])) return OPCODE_REG_ERROR;
    if(unlikely(wr_info_inv->type==LOCAL)) return OPCODE_REG_ERROR;
    if(unlikely(!wr_info_inv->std.qpts[qpt])) return OPCODE_REG_ERROR;
    if(unlikely(is_registered(opcode_group_inv))) return OPCODE_IN_USE;
    if(unlikely(!(wr_info_inv->mask & WR_INV_MASK))) return ARGUMENTS_INVALID;
  }
  strcpy(startname, basename);
  strcpy(middlename, basename);
  strcpy(endname, basename);
  strcpy(onlyname, basename);
  strcat(startname, "_start");
  strcat(middlename, "_middle");
  strcat(endname, "_end");
  strcat(onlyname, "_only");
  if(immdt==YES) {
    strcat(endname, "_with_immdt");  // throughout, one tiny way we're altering the functionality of the
    strcat(onlyname, "_with_immdt"); // existing code is that these constructed names will be slightly
                                     // different than the names that were previously used
  } else if(immdt==BOTH) {
    strcpy(endname_immdt, basename);
    strcpy(onlyname_immdt, basename);
    strcat(endname_immdt, "_end_with_immdt");
    strcat(onlyname_immdt, "_only_with_immdt");
  }
  if(invalidate==YES) {
    strcat(endname, "_with_inv");
    strcat(onlyname, "_with_inv");
  } else if(invalidate==BOTH) {
    strcpy(endname_inv, basename);
    strcpy(onlyname_inv, basename);
    strcat(endname_inv, "_end_with_inv");
    strcat(onlyname_inv, "_only_with_inv");
  }

  WITH_CHECK(__register_req_opcode(
      start_opcode_num, startname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ requiresReceive,
      /* postComplete    = */ false,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* comp_swap       = */ comp_swap,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ false
  ), err0)
  WITH_CHECK(__register_req_opcode(
      middle_opcode_num, middlename, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ false,
      /* postComplete    = */ false,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* comp_swap       = */ comp_swap,
      /* start           = */ false,
      /* middle          = */ true,
      /* end             = */ false
  ), err1)
  WITH_CHECK(__register_req_opcode(
      end_opcode_num, endname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ (immdt==YES),
      /* postComplete    = */ wr_info->mask & WR_COMP_MASK,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* comp_swap       = */ comp_swap,
      /* start           = */ false,
      /* middle          = */ false,
      /* end             = */ true
  ), err2)
  WITH_CHECK(__register_req_opcode(
      only_opcode_num, onlyname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ requiresReceive || (immdt==YES),
      /* postComplete    = */ wr_info->mask & WR_COMP_MASK,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* comp_swap       = */ comp_swap,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ true
  ), err3)
  if(immdt==BOTH) {
    bool postComplete_immdt = wr_info_immdt->mask & WR_COMP_MASK;  // always TRUE
    WITH_CHECK(__register_req_opcode(
        end_opcode_num_immdt, endname_immdt, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_immdt, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ !requiresReceive,
        /* postComplete    = */ postComplete_immdt,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* comp_swap       = */ comp_swap,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true
    ), err4)
    WITH_CHECK(__register_req_opcode(
        only_opcode_num_immdt, onlyname_immdt, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_immdt, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ true,
        /* postComplete    = */ postComplete_immdt,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* comp_swap       = */ comp_swap,
        /* start           = */ true,
        /* middle          = */ false,
        /* end             = */ true
    ), err_immdt)
  }
  if(invalidate==BOTH) {
    bool postComplete_inv = wr_info_inv->mask & WR_COMP_MASK;  // always TRUE
    WITH_CHECK(__register_req_opcode(
        end_opcode_num_inv, endname_inv, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_inv, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ false,
        /* postComplete    = */ postComplete_inv,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* comp_swap       = */ comp_swap,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true
    ), err4)
    WITH_CHECK(__register_req_opcode(
        only_opcode_num_inv, onlyname_inv, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_inv, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ requiresReceive,
        /* postComplete    = */ postComplete_inv,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* comp_swap       = */ comp_swap,
        /* start           = */ true,  // the (one) existing ONLY_WITH_INVALIDATE opcode has 'false' here,
                                       // but I'm assuming that's an error/typo
        /* middle          = */ false,
        /* end             = */ true
    ), err_inv)
  }
  // Successfully registered all req_opcodes.  Now register with the wr_opcodes
  // (and fill in containingGroup for the req_opcodes)
  opcode_group->is_series = true;
  opcode_group->opcode_set.start_opcode_num = start_opcode_num;
  opcode_group->opcode_set.middle_opcode_num = middle_opcode_num;
  opcode_group->opcode_set.end_opcode_num = end_opcode_num;
  opcode_group->opcode_set.only_opcode_num = only_opcode_num;
  rxe_opcode[start_opcode_num].containingGroup = *opcode_group;
  rxe_opcode[middle_opcode_num].containingGroup = *opcode_group;
  rxe_opcode[end_opcode_num].containingGroup = *opcode_group;
  rxe_opcode[only_opcode_num].containingGroup = *opcode_group;
  if(immdt==BOTH) {
    opcode_group_immdt->is_series = true;
    opcode_group_immdt->opcode_set.start_opcode_num = start_opcode_num;
    opcode_group_immdt->opcode_set.middle_opcode_num = middle_opcode_num;
    opcode_group_immdt->opcode_set.end_opcode_num = end_opcode_num_immdt;
    opcode_group_immdt->opcode_set.only_opcode_num = only_opcode_num_immdt;
    rxe_opcode[end_opcode_num_immdt].containingGroup = *opcode_group_immdt;
    rxe_opcode[only_opcode_num_immdt].containingGroup = *opcode_group_immdt;
  }
  if(invalidate==BOTH) {
    opcode_group_inv->is_series = true;
    opcode_group_inv->opcode_set.start_opcode_num = start_opcode_num;
    opcode_group_inv->opcode_set.middle_opcode_num = middle_opcode_num;
    opcode_group_inv->opcode_set.end_opcode_num = end_opcode_num_inv;
    opcode_group_inv->opcode_set.only_opcode_num = only_opcode_num_inv;
    rxe_opcode[end_opcode_num_inv].containingGroup = *opcode_group_inv;
    rxe_opcode[only_opcode_num_inv].containingGroup = *opcode_group_inv;
  }
  return ret;

err_immdt:
  __deregister_opcode(end_opcode_num_immdt);
  goto err4;
err_inv:
  __deregister_opcode(end_opcode_num_inv);
  goto err4;
err4:
  __deregister_opcode(only_opcode_num);
err3:
  __deregister_opcode(end_opcode_num);
err2:
  __deregister_opcode(middle_opcode_num);
err1:
  __deregister_opcode(start_opcode_num);
err0:
  return ret;
}

register_opcode_status register_ack_opcode_series(
    unsigned start_opcode_num,
    unsigned middle_opcode_num,
    unsigned end_opcode_num,
    unsigned only_opcode_num,
    char* basename,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
) {
  register_opcode_status ret = OPCODE_OK;
  size_t len = strlen(basename);
  char startname[64], middlename[64], endname[64], onlyname[64];
  struct rxe_opcode_group thisGroup;
  if(unlikely(len > 56 || len == 0)) return NAME_INVALID;
  strcpy(startname, basename);
  strcpy(middlename, basename);
  strcpy(endname, basename);
  strcpy(onlyname, basename);
  strcat(startname, "_start");
  strcat(middlename, "_middle");
  strcat(endname, "_end");
  strcat(onlyname, "_only");
  thisGroup.is_series = true;
  thisGroup.opcode_set.start_opcode_num = start_opcode_num;
  thisGroup.opcode_set.middle_opcode_num = middle_opcode_num;
  thisGroup.opcode_set.end_opcode_num = end_opcode_num;
  thisGroup.opcode_set.only_opcode_num = only_opcode_num;
  WITH_CHECK(__register_ack_opcode(start_opcode_num, startname,
      handle_incoming, atomicack, true, false, false), err0)
  WITH_CHECK(__register_ack_opcode(middle_opcode_num, middlename,
      handle_incoming, atomicack, false, true, false), err1)
  WITH_CHECK(__register_ack_opcode(end_opcode_num, endname,
      handle_incoming, atomicack, false, false, true), err2)
  WITH_CHECK(__register_ack_opcode(only_opcode_num, onlyname,
      handle_incoming, atomicack, true, false, true), err3)
  return ret;

err3:
  __deregister_opcode(end_opcode_num);
err2:
  __deregister_opcode(middle_opcode_num);
err1:
  __deregister_opcode(start_opcode_num);
err0:
  return ret;
}

void irdma_init(void) {
  unsigned i;
  struct rxe_opcode_info* info;
  for(i = 0; i < IRDMA_MAX_WR_OPCODES; i++) {
    rxe_wr_opcode_info[i].name[0] = '\0';  // mark as free
  }
  for(i = 0; i < IRDMA_MAX_RXE_OPCODES; i++) {
    rxe_opcode[i].name[0] = '\0';  // mark as free
  }

  // custom-register IRDMA_OPCODE_NAK
  info = &rxe_opcode[IRDMA_OPCODE_NAK];
  strcpy(info->name, "IRDMA_OPCODE_NAK");
  info->mask = RXE_START_MASK | RXE_END_MASK | RXE_AETH_MASK;
  info->is_ack = true;
  info->ack.handle_incoming = NULL;  // handled specially in the code,
                                     // rather than through this function
  info->qpt = IB_QPT_RC;  // all 'ack' opcodes are RC-only
  computeLengthAndOffset(info);
  info->containingGroup.is_series = false;
  info->containingGroup.opcode_num = IRDMA_OPCODE_NAK;
}
