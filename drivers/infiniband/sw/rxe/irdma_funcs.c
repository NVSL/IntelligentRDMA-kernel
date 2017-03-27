#include "irdma_funcs.h"
#include "irdma_helpers.h"
#include "rxe_loc.h"

struct resp_res* get_new_resource(struct irdma_context* ic) {
  return __get_new_resource(ic->qp);
}

struct resp_res* get_existing_resource(struct irdma_context* ic, u32 psn) {
  int i;
  for(i = 0; i < ic->qp->attr.max_rd_atomic; i++) {
    struct resp_res *res = &ic->qp->resp.resources[i];
    if(res->type == 0) continue;
    if(psn_compare(psn, res->first_psn) >= 0 &&
       psn_compare(psn, res->last_psn) <= 0) {
      return res;
    }
  }
  return NULL;
}

int send_ack_packet(
    struct irdma_context* ic,
    struct irdma_mem* payload,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn
) {
  struct rxe_wr_opcode_info* wr_info = &rxe_wr_opcode_info[rxe_opcode[req_pkt->opcode].req.wr_opcode_num];
  struct rxe_opcode_group ack_opcode_group = wr_info->std.ack_opcode_group;
  unsigned ack_opcode_num = ack_opcode_group.opcode_num;
    // send_ack_packet only called with single ack_opcodes, not series (for now)
  if((syndrome & AETH_TYPE_MASK) != AETH_ACK) {
    pr_err("Can't send ack packet with NAK syndrome 0x%x\n", syndrome);
    return -1;  // what should the error code be here?
  }
  return __send_packet_with_opcode(ic->qp, payload, req_pkt, syndrome, psn, ack_opcode_num);
}

int send_nak_packet(
    struct irdma_context* ic,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn
) {
  if((syndrome & AETH_TYPE_MASK) == AETH_ACK) {
    pr_err("Can't send NAK packet with ack syndrome 0x%x\n", syndrome);
    return -1;  // what should the error code be here?
  }
  return __send_packet_with_opcode(ic->qp, NULL, req_pkt, syndrome, psn, IB_OPCODE_RC_ACKNOWLEDGE);
}

int resend_packet(
    struct irdma_context* ic,
    struct rxe_pkt_info* pkt,
    struct sk_buff* skb,
    struct rxe_dev* rxe,
    bool atomicack
) {
  return __send_packet_raw(ic->qp, pkt, skb, rxe, atomicack);
}

void do_class_ac_error(struct irdma_context* ic, u8 syndrome,
			      enum ib_wc_status status) {
    __do_class_ac_error(ic->qp, syndrome, status);
}
