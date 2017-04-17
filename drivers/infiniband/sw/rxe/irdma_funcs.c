#include "irdma_funcs.h"
#include "irdma_helpers.h"
#include "rxe_loc.h"

struct rxe_mem* get_mem(struct irdma_context* ic, struct rxe_pkt_info* pkt, u32 rkey, u64 va, u32 resid, int access) {
  return __get_mem(ic->qp, pkt, rkey, va, resid, access);
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

int copy_to_dma_loc(struct irdma_context* ic, struct rxe_dma_info* dma, void* addr, int len) {
  struct rxe_dev* rxe = to_rdev(ic->qp->ibqp.device);
  return copy_data(rxe, ic->qp->pd, IB_ACCESS_LOCAL_WRITE, dma, addr, len, to_mem_obj, NULL);
}

int send_ack_packet_or_series(
    struct irdma_context* ic,
    struct irdma_mem* payload,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn
) {
  struct rxe_wr_opcode_info* wr_info = &rxe_wr_opcode_info[rxe_opcode[req_pkt->opcode].req.wr_opcode_num];
  struct rxe_opcode_group ack_opcode_group = wr_info->std.ack_opcode_group;
  if((syndrome & AETH_TYPE_MASK) != AETH_ACK) {
    pr_err("Can't send ack packet with NAK syndrome 0x%x\n", syndrome);
    return -1;  // what should the error code be here?
  }
  if(ack_opcode_group.is_series) {
    int mtu = ic->qp->mtu;
    struct resp_res *res;

    // Initialize series-sending operation
    if(ic->qp->resp.res) {
      pr_err("tried to initialize ack series send while one was already in progress\n");
      return -1;  // or what other error code?
    }
    res = __get_new_resource(ic->qp);
    res->type = IRDMA_RES_READ;
    res->state = rdatm_res_state_new;
    res->read.va = payload->va;
    res->read.va_org = payload->va;
    res->first_psn = psn;
    res->cur_psn = psn;
    if(reth_len(req_pkt)) {
      res->last_psn = (psn + (reth_len(req_pkt) + mtu - 1) / mtu - 1) & BTH_PSN_MASK;
    } else {
      res->last_psn = res->first_psn;
    }
    res->read.length = payload->length;
    res->read.resid = payload->length;
    res->read.rkey = reth_rkey(req_pkt);
      // read.rkey appears to only be used in handle_duplicate, where they ensure
      // the duplicate request has the same rkey as the old one.  Could we replace
      // that check in handle_duplicate with just the original rkey validation?
      // Then we avoid (a) referencing this rkey here (I imagine this might not be
      // the right rkey if you use this function with a different payload than the
      // existing caller does), or (b) having to pass in an rkey to this function,
      // but only sometimes, depending on whether it's a series ack or not
    res->read.aeth_syndrome = syndrome;
    // res inherits the reference to mr from payload
    // or if payload is local, then this is just NULL anyway, and read.mr==NULL also indicates local
    res->read.mr = payload->mr;
    payload->mr = NULL;
    ic->qp->resp.res = res;  // this signals 'series send in progress' to rxe_responder
    return __continue_sending_ack_series(ic->qp, req_pkt);
  } else {
    unsigned opcode_num = ack_opcode_group.opcode_num;
    return __send_packet_with_opcode(ic->qp, payload, req_pkt, syndrome, psn, opcode_num);
  }
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
  return __send_packet_with_opcode(ic->qp, NULL, req_pkt, syndrome, psn, IRDMA_OPCODE_NAK);
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
