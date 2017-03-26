#include "irdma.h"
#include "rxe_hdr.h"
#include <linux/string.h>

struct rxe_wr_opcode_info rxe_wr_opcode_info[IRDMA_MAX_WR_OPCODES];
struct rxe_opcode_info rxe_opcode[IRDMA_MAX_RXE_OPCODES];

void irdma_init(void) {
  unsigned i;
  for(i = 0; i < IRDMA_MAX_WR_OPCODES; i++) {
    rxe_wr_opcode_info[i].name[0] = '\0';  // mark as free
  }
  for(i = 0; i < IRDMA_MAX_RXE_OPCODES; i++) {
    rxe_opcode[i].name[0] = '\0';  // mark as free
  }
}

register_opcode_status register_wr_opcode(
    unsigned wr_opcode_num,
    char* name,
    enum ib_qp_type* qpts,
    unsigned num_qpts,
    bool series,
    enum rxe_wr_mask type,
    bool immdt,
    bool invalidate,
    bool wr_inline,
    bool alwaysEnableSolicited,
    enum ib_wc_opcode wc_opcode,
    unsigned ack_opcode_num
) {
  unsigned i;
  struct rxe_opcode_info ack_opcode_info = rxe_opcode[ack_opcode_num];
  if(wr_opcode_num >= IRDMA_MAX_WR_OPCODES) return OPCODE_INVALID;
  if(strlen(name) > 63) return OPCODE_INVALID;
  if(!name[0]) return OPCODE_INVALID;
  if(rxe_wr_opcode_info[wr_opcode_num].name[0]) return OPCODE_IN_USE;  // name=="" indicates free
    // TODO if someone tries to actually use a not-yet-registered wr_opcode, give a suitable error msg
  if(!ack_opcode_info.name[0]) return OPCODE_INVALID;
  if(!ack_opcode_info.is_ack) return OPCODE_INVALID;
  if(!(ack_opcode_info.mask & RXE_START_MASK)) return OPCODE_INVALID;
    // the above line doesn't catch all restrictions we wish to make on the
    // properties of ack_opcode_info, but it will at least catch some mistakes
    // (The properties we require are that ack_opcode is either a single opcode,
    // or the 'start' opcode of a series; the above line will also pass
    // opcodes which are 'only' components of a series)
  if(unlikely(immdt && invalidate)) return OPCODE_INVALID;
    // although conceptually there's no problem with immdt && invalidate (as far as I know), it
    // can't be allowed in the existing implementation due to, e.g., the definition of the ib_wc
    // or rxe_send_wr structs (probably among other things)
  strcpy(rxe_wr_opcode_info[wr_opcode_num].name, name);
  rxe_wr_opcode_info[wr_opcode_num].is_series = series;
  for(i = 0; i < WR_MAX_QPT; i++) {
    // mark opcode num or set not-yet-registered for each qpt
    if(series) rxe_wr_opcode_info[wr_opcode_num].opcodes[i].opcode_set.start_opcode_num = 0;
    else rxe_wr_opcode_info[wr_opcode_num].opcodes[i].opcode_num = 0;
  }
  rxe_wr_opcode_info[wr_opcode_num].mask =
      (wr_inline ? WR_INLINE_MASK : 0)
    | (immdt ? WR_IMMDT_MASK : 0)
    | (invalidate ? WR_INV_MASK : 0)
    | (alwaysEnableSolicited ? WR_SOLICITED_MASK : 0)
    | type;
  for(i = 0; i < WR_MAX_QPT; i++) rxe_wr_opcode_info[wr_opcode_num].qpts[i] = false;
  for(i = 0; i < num_qpts; i++) rxe_wr_opcode_info[wr_opcode_num].qpts[qpts[i]] = true;
  rxe_wr_opcode_info[wr_opcode_num].wc_opcode = wc_opcode;
  rxe_wr_opcode_info[wr_opcode_num].ack_opcode_num = ack_opcode_num;
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
// series_id:
//   For 'series' opcodes: the 'start' opcode for the series
//   For 'single' opcodes: the opcode itself
//   We choose this assignment so that a series_id is shared among all members of the series
//   and 'single' opcodes have a unique series_id, not shared with any other opcode (series or not)
static register_opcode_status __register_req_opcode(
    unsigned opcode_num,
    char* name,
    IRDMA_REQ_OPNUM irdma_req_opnum,
    handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
    handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
    unsigned wr_opcode_num,
    enum ib_qp_type qpt,
    bool immdt, bool invalidate,
    bool requiresReceive, bool postComplete, unsigned char perms, bool sched_priority,
    /* internal arguments */ bool start, bool middle, bool end, unsigned series_id
) {
  enum rxe_hdr_mask mask;
  if(unlikely(opcode_num >= IRDMA_MAX_RXE_OPCODES)) return OPCODE_INVALID;
  if(unlikely(opcode_num == 0)) return OPCODE_INVALID;
  if(unlikely(!name[0])) return OPCODE_INVALID;
  if(unlikely(rxe_opcode[opcode_num].name[0])) return OPCODE_IN_USE;  // name=="" indicates free
    // TODO if someone tries to actually use a not-yet-registered req_opcode, give a suitable error msg
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
    | SET_IF(invalidate, RXE_IETH_MASK)
    | SET_IF(requiresReceive, RXE_RWR_MASK)
    | SET_IF(postComplete, RXE_COMP_MASK)
    | SET_IF(start, RXE_START_MASK)
    | SET_IF(middle, RXE_MIDDLE_MASK)
    | SET_IF(end, RXE_END_MASK)
    | SET_IF(sched_priority, IRDMA_SCHED_PRIORITY_MASK)
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
  strcpy(rxe_opcode[opcode_num].name, name);
  rxe_opcode[opcode_num].mask = mask;
  rxe_opcode[opcode_num].is_ack = false;
  rxe_opcode[opcode_num].req.irdma_opnum = irdma_req_opnum;
  rxe_opcode[opcode_num].req.wr_opcode_num = wr_opcode_num;
  rxe_opcode[opcode_num].req.handle_incoming = handle_incoming;
  rxe_opcode[opcode_num].req.handle_duplicate = handle_duplicate;
  rxe_opcode[opcode_num].req.perms = perms;
  rxe_opcode[opcode_num].qpt = qpt;
  rxe_opcode[opcode_num].series_id = series_id;
  computeLengthAndOffset(&rxe_opcode[opcode_num]);
  return OPCODE_OK;
}

// internal function, used by the public-facing 'register_single_ack_opcode' and
//   'register_ack_opcode_series'
// series_id: see comments on __register_req_opcode
static register_opcode_status __register_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack,
    /* internal arguments */ bool start, bool middle, bool end, unsigned series_id
) {
  enum rxe_hdr_mask mask;
  if(unlikely(opcode_num >= IRDMA_MAX_RXE_OPCODES)) return OPCODE_INVALID;
  if(unlikely(opcode_num == 0)) return OPCODE_INVALID;
  if(unlikely(!name[0])) return OPCODE_INVALID;
  if(unlikely(rxe_opcode[opcode_num].name[0])) return OPCODE_IN_USE;  // name=="" indicates free
    // TODO if someone tries to actually use a not-yet-registered ack_opcode, give a suitable error msg
  if(unlikely(strlen(name) > 63)) return OPCODE_INVALID;
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
  strcpy(rxe_opcode[opcode_num].name, name);
  rxe_opcode[opcode_num].mask = mask;
  rxe_opcode[opcode_num].is_ack = true;
  rxe_opcode[opcode_num].ack.handle_incoming = handle_incoming;
  rxe_opcode[opcode_num].qpt = IB_QPT_RC;  // all 'ack' opcodes are RC-only
  rxe_opcode[opcode_num].series_id = series_id;
  computeLengthAndOffset(&rxe_opcode[opcode_num]);
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
  bool requiresReceive, bool postComplete, unsigned char perms, bool sched_priority
) {
  register_opcode_status st;
  if(unlikely(!rxe_wr_opcode_info[wr_opcode_num].name[0])) return OPCODE_INVALID;
  if(unlikely(qpt!=IB_QPT_UD && rxe_wr_opcode_info[wr_opcode_num].is_series)) return OPCODE_INVALID;
    // Ugly, but IB_QPT_UD needs to be allowed to register single req_opcodes with series wr_opcodes
    // Any function which checks rxe_wr_opcode_info[x].is_series needs to be aware of this exception too
  if(unlikely(!rxe_wr_opcode_info[wr_opcode_num].qpts[qpt])) return OPCODE_INVALID;
    // More elegant would be, don't make the user declare supported qpts when registering wr_opcode,
    //   and instead just assume that qpts with registered opcodes are supported, and without are not
    //   However, the existing code marks some wr_opcodes as compatible with IB_QPT_SMI and IB_QPT_GSI,
    //   and others not; and doesn't register opcodes for SMI or GSI.  So we kind of have to keep this,
    //   just to preserve that information?  I wish I understood more about SMI / GSI and why they
    //   don't have opcodes (in rxe_opcode.c in the existing code).
  if(unlikely(rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_num != 0)) return OPCODE_IN_USE;
  st = __register_req_opcode(
      opcode_num,
      name,
      irdma_req_opnum,
      handle_incoming,
      handle_duplicate,
      wr_opcode_num,
      qpt,
      /* immdt      = */ rxe_wr_opcode_info[wr_opcode_num].mask & WR_IMMDT_MASK,
      /* invalidate = */ rxe_wr_opcode_info[wr_opcode_num].mask & WR_INV_MASK,
      requiresReceive, postComplete, perms, sched_priority,
      /* start     = */ true,   /* \                           */
      /* middle    = */ false,  /*  |--  (treat as an 'only')  */
      /* end       = */ true,   /* /                           */
      /* series_id = */ opcode_num
      );
  if(st == OPCODE_OK) {
    // don't register with the wr_opcode if the rxe_opcode registration failed
    rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_num = opcode_num;
  }
  return st;
}

register_opcode_status register_single_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
) {
  return __register_ack_opcode(
      opcode_num,
      name,
      handle_incoming,
      atomicack,
      /* start     = */ true,   /* \                           */
      /* middle    = */ false,  /*  |--  (treat as an 'only')  */
      /* end       = */ true,   /* /                           */
      /* series_id = */ opcode_num
      );
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
  bool requiresReceive, bool postComplete, unsigned char perms, bool sched_priority
) {
  // TODO: Here and in register_ack_opcode_series make sure that we're correctly handling the (error) case where
  //   the user passes in duplicates among the (not-ignored) rxe_opcodes or (not-ignored) wr_opcodes
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
  if(unlikely(!rxe_wr_opcode_info[wr_opcode_num].name[0])) return OPCODE_INVALID;
  if(unlikely(!rxe_wr_opcode_info[wr_opcode_num].is_series)) return OPCODE_INVALID;
  if(unlikely(!rxe_wr_opcode_info[wr_opcode_num].qpts[qpt])) return OPCODE_INVALID;
  if(unlikely(rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_set.start_opcode_num != 0)) return OPCODE_IN_USE;
  if(unlikely((rxe_wr_opcode_info[wr_opcode_num].mask & WR_IMMDT_MASK) && immdt!=YES)) return OPCODE_INVALID;
  if(unlikely((rxe_wr_opcode_info[wr_opcode_num].mask & WR_INV_MASK) && invalidate!=YES)) return OPCODE_INVALID;
  if(unlikely((!(rxe_wr_opcode_info[wr_opcode_num].mask & WR_IMMDT_MASK)) && immdt==YES)) return OPCODE_INVALID;
  if(unlikely((!(rxe_wr_opcode_info[wr_opcode_num].mask & WR_INV_MASK)) && invalidate==YES)) return OPCODE_INVALID;
  if(immdt==BOTH) {
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_immdt].name[0])) return OPCODE_INVALID;
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_immdt].is_series)) return OPCODE_INVALID;
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_immdt].qpts[qpt])) return OPCODE_INVALID;
    if(unlikely(rxe_wr_opcode_info[wr_opcode_num_immdt].opcodes[qpt].opcode_set.start_opcode_num != 0)) return OPCODE_IN_USE;
    if(unlikely(!(rxe_wr_opcode_info[wr_opcode_num_immdt].mask & WR_IMMDT_MASK))) return OPCODE_INVALID;
  }
  if(invalidate==BOTH) {
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_inv].name[0])) return OPCODE_INVALID;
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_inv].is_series)) return OPCODE_INVALID;
    if(unlikely(!rxe_wr_opcode_info[wr_opcode_num_inv].qpts[qpt])) return OPCODE_INVALID;
    if(unlikely(rxe_wr_opcode_info[wr_opcode_num_inv].opcodes[qpt].opcode_set.start_opcode_num != 0)) return OPCODE_IN_USE;
    if(unlikely(!(rxe_wr_opcode_info[wr_opcode_num_inv].mask & WR_INV_MASK))) return OPCODE_INVALID;
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
  ret = __register_req_opcode(
      start_opcode_num, startname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ requiresReceive,
      /* postComplete    = */ false,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ false,
      /* series_id       = */ start_opcode_num
      );
  if(ret) goto err0;
  ret = __register_req_opcode(
      middle_opcode_num, middlename, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ false,
      /* invalidate      = */ false,
      /* requiresReceive = */ false,
      /* postComplete    = */ false,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* start           = */ false,
      /* middle          = */ true,
      /* end             = */ false,
      /* series_id       = */ start_opcode_num
      );
  if(ret) goto err1;
  ret = __register_req_opcode(
      end_opcode_num, endname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ (immdt==YES),
      /* postComplete    = */ postComplete,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* start           = */ false,
      /* middle          = */ false,
      /* end             = */ true,
      /* series_id       = */ start_opcode_num
      );
  if(ret) goto err2;
  ret = __register_req_opcode(
      only_opcode_num, onlyname, irdma_req_opnum,
      handle_incoming, handle_duplicate, wr_opcode_num, qpt,
      /* immdt           = */ (immdt==YES),
      /* invalidate      = */ (invalidate==YES),
      /* requiresReceive = */ requiresReceive || (immdt==YES),
      /* postComplete    = */ postComplete,
      /* perms           = */ perms,
      /* sched_priority  = */ sched_priority,
      /* start           = */ true,
      /* middle          = */ false,
      /* end             = */ true,
      /* series_id       = */ start_opcode_num
      );
  if(ret) goto err3;
  if(immdt==BOTH) {
    ret = __register_req_opcode(
        end_opcode_num_immdt, endname_immdt, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_immdt, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ !requiresReceive,
        /* postComplete    = */ true,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true,
        /* series_id       = */ start_opcode_num
      );
    if(ret) goto err4;
    ret = __register_req_opcode(
        only_opcode_num_immdt, onlyname_immdt, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_immdt, qpt,
        /* immdt           = */ true,
        /* invalidate      = */ false,
        /* requiresReceive = */ true,
        /* postComplete    = */ true,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* start           = */ true,
        /* middle          = */ false,
        /* end             = */ true,
        /* series_id       = */ start_opcode_num
        );
    if(ret) {
      __deregister_opcode(end_opcode_num_immdt);
      goto err4;
    }
  }
  if(invalidate==BOTH) {
    ret = __register_req_opcode(
        end_opcode_num_inv, endname_inv, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_inv, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ false,
        /* postComplete    = */ true,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* start           = */ false,
        /* middle          = */ false,
        /* end             = */ true,
        /* series_id       = */ start_opcode_num
        );
    if(ret) goto err4;
    ret = __register_req_opcode(
        only_opcode_num_inv, onlyname_inv, irdma_req_opnum,
        handle_incoming, handle_duplicate, wr_opcode_num_inv, qpt,
        /* immdt           = */ false,
        /* invalidate      = */ true,
        /* requiresReceive = */ requiresReceive,
        /* postComplete    = */ true,
        /* perms           = */ perms,
        /* sched_priority  = */ sched_priority,
        /* start           = */ true,  // the (one) existing ONLY_WITH_INVALIDATE opcode has 'false' here,
                                       // but I'm assuming that's an error/typo
        /* middle          = */ false,
        /* end             = */ true,
        /* series_id       = */ start_opcode_num
        );
    if(ret) {
      __deregister_opcode(end_opcode_num_inv);
      goto err4;
    }
  }
  // Successfully registered all req_opcodes.  Now register with the wr_opcodes
  rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_set.start_opcode_num = start_opcode_num;
  rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_set.middle_opcode_num = middle_opcode_num;
  rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_set.end_opcode_num = end_opcode_num;
  rxe_wr_opcode_info[wr_opcode_num].opcodes[qpt].opcode_set.only_opcode_num = only_opcode_num;
  if(immdt==BOTH) {
    rxe_wr_opcode_info[wr_opcode_num_immdt].opcodes[qpt].opcode_set.start_opcode_num = start_opcode_num;
    rxe_wr_opcode_info[wr_opcode_num_immdt].opcodes[qpt].opcode_set.middle_opcode_num = middle_opcode_num;
    rxe_wr_opcode_info[wr_opcode_num_immdt].opcodes[qpt].opcode_set.end_opcode_num = end_opcode_num_immdt;
    rxe_wr_opcode_info[wr_opcode_num_immdt].opcodes[qpt].opcode_set.only_opcode_num = only_opcode_num_immdt;
  }
  if(invalidate==BOTH) {
    rxe_wr_opcode_info[wr_opcode_num_inv].opcodes[qpt].opcode_set.start_opcode_num = start_opcode_num;
    rxe_wr_opcode_info[wr_opcode_num_inv].opcodes[qpt].opcode_set.middle_opcode_num = middle_opcode_num;
    rxe_wr_opcode_info[wr_opcode_num_inv].opcodes[qpt].opcode_set.end_opcode_num = end_opcode_num_inv;
    rxe_wr_opcode_info[wr_opcode_num_inv].opcodes[qpt].opcode_set.only_opcode_num = only_opcode_num_inv;
  }
  return ret;

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
  if(unlikely(len > 56 || len == 0)) return OPCODE_INVALID;
  strcpy(startname, basename);
  strcpy(middlename, basename);
  strcpy(endname, basename);
  strcpy(onlyname, basename);
  strcat(startname, "_start");
  strcat(middlename, "_middle");
  strcat(endname, "_end");
  strcat(onlyname, "_only");
  ret = __register_ack_opcode(start_opcode_num, startname,
      handle_incoming, atomicack, true, false, false, start_opcode_num);
  if(ret) goto err0;
  ret = __register_ack_opcode(middle_opcode_num, middlename,
      handle_incoming, atomicack, false, true, false, start_opcode_num);
  if(ret) goto err1;
  ret = __register_ack_opcode(end_opcode_num, endname,
      handle_incoming, atomicack, false, false, true, start_opcode_num);
  if(ret) goto err2;
  ret = __register_ack_opcode(only_opcode_num, onlyname,
      handle_incoming, atomicack, true, false, true, start_opcode_num);
  if(ret) goto err3;
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
