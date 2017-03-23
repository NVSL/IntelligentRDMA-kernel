#include "irdma_funcs.h"
#include "rxe_loc.h"

struct resp_res* get_new_resource(struct irdma_context* ic) {
  struct resp_res* res = &(ic->qp->resp.resources[ic->qp->resp.res_head]);
  free_rd_atomic_resource(ic->qp, res);
  rxe_advance_resp_resource(ic->qp);
  return res;
}

// returns NULL if not found
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

int send_packet(
    struct irdma_context* ic,
    unsigned opcode_num,
    struct irdma_mem* payload,
    struct rxe_pkt_info* cur_pkt,
    u8 syndrome,
    u32 psn
) {
  struct rxe_pkt_info new_pkt;
  struct sk_buff *skb;
  struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);
  u32 crc = 0;
  int err;
  u32* p;
  int paylen;
  int pad;
  bool atomicack = rxe_opcode[opcode_num].mask & RXE_ATMACK_MASK;

  if(unlikely(!(rxe_opcode[opcode_num].ack))) {
      pr_err("Tried to send_packet but specifying a non-ack opcode\n");
      return -EINVAL;
  }

  // allocate packet
  pad = (-payload->length) & 0x3;
  paylen = rxe_opcode[opcode_num].length + payload->length + pad + RXE_ICRC_SIZE;
  skb = rxe->ifc_ops->init_packet(rxe, &ic->qp->pri_av, paylen, &new_pkt);
  if(!skb) return -ENOMEM;
  new_pkt.qp = ic->qp;
  new_pkt.opcode = opcode_num;
  new_pkt.mask = rxe_opcode[opcode_num].mask;
  new_pkt.irdma_opnum = rxe_opcode[opcode_num].irdma_opnum;
  new_pkt.offset = cur_pkt->offset;  // can I change this to rxe_opcode[opcode_num].offset?
  new_pkt.paylen = paylen;

  // fill in bth using the request packet headers
  memcpy(new_pkt.hdr, cur_pkt->hdr, cur_pkt->offset + RXE_BTH_BYTES);
  // third argument could be new_pkt.offset + RXE_BTH_BYTES
  bth_set_opcode(&new_pkt, opcode_num);
  bth_set_qpn(&new_pkt, ic->qp->attr.dest_qp_num);
  bth_set_pad(&new_pkt, pad);
  bth_set_se(&new_pkt, 0);
  bth_set_psn(&new_pkt, psn);
  bth_set_ack(&new_pkt, 0);
  new_pkt.psn = psn;

  if(new_pkt.mask & RXE_AETH_MASK) {
      aeth_set_syn(&new_pkt, syndrome);
      aeth_set_msn(&new_pkt, ic->qp->resp.msn);
  }
  if(new_pkt.mask & RXE_ATMACK_MASK) {
      atmack_set_orig(&new_pkt, ic->qp->resp.atomic_orig);
  }

  err = rxe->ifc_ops->prepare(rxe, &new_pkt, skb, &crc);
  if(err) {
      kfree_skb(skb);
      return -ENOMEM;
  }

  if(payload) {
    err = rxe_mem_copy(payload->mr, payload->va, payload_addr(&new_pkt), payload->length, from_mem_obj, &crc);
    if(err) pr_err("Failed copying memory\n");  // but for some reason, keep going
  }
  p = payload_addr(&new_pkt) + payload->length + bth_pad(&new_pkt);
  *p = ~crc;

  err = send_packet_raw(ic, &new_pkt, skb, rxe, atomicack);
  if(err) pr_err_ratelimited("Failed sending packet with opcode %s\n", rxe_opcode[opcode_num].name);

  return err;
}

int send_packet_raw(
    struct irdma_context* ic,
    struct rxe_pkt_info* pkt,
    struct sk_buff* skb,
    struct rxe_dev* rxe,
    bool atomicack
) {
  struct resp_res *res;
  struct sk_buff *skb_copy;
  int err;
  if(atomicack) {
    skb_copy = skb_clone(skb, GFP_ATOMIC);
    if(skb_copy) {
      rxe_add_ref(ic->qp);  // for the new SKB
    } else {
      pr_warn("Could not clone atomic response\n");
      return -ENOMEM;
    }
    res = get_new_resource(ic);
    memcpy(SKB_TO_PKT(skb), pkt, sizeof(skb->cb));
    res->type = IRDMA_ATOMIC;
    res->atomic.skb = skb;
    res->first_psn = pkt->psn;
    res->last_psn = pkt->psn;
    res->cur_psn = pkt->psn;
  }

  err = rxe_xmit_packet(rxe, ic->qp, pkt, atomicack ? skb_copy : skb);
  if(err) {
    if(atomicack) rxe_drop_ref(ic->qp);
    kfree_skb(atomicack ? skb_copy : skb);
  }
  return err;
}

void do_class_ac_error(struct irdma_context* ic, u8 syndrome,
			      enum ib_wc_status status) {
	ic->qp->resp.aeth_syndrome = syndrome;
	ic->qp->resp.status = status;

	/* indicate that we should go through the ERROR state */
	ic->qp->resp.goto_error	= 1;
}
