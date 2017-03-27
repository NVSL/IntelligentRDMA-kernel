#include "irdma_helpers.h"
#include "rxe_loc.h"

void __do_class_ac_error(struct rxe_qp* qp, u8 syndrome, enum ib_wc_status status) {
	qp->resp.aeth_syndrome = syndrome;
	qp->resp.status = status;

	/* indicate that we should go through the ERROR state */
	qp->resp.goto_error	= 1;
}

void __cleanup(struct rxe_qp *qp, struct rxe_pkt_info *pkt) {
	struct sk_buff *skb;

	if (pkt) {
		skb = skb_dequeue(&qp->req_pkts);
		rxe_drop_ref(qp);
		kfree_skb(skb);
	}

	if (qp->resp.mr) {
		rxe_drop_ref(qp->resp.mr);
		qp->resp.mr = NULL;
	}
}

struct resp_res* __get_new_resource(struct rxe_qp* qp) {
  struct resp_res* res = &(qp->resp.resources[qp->resp.res_head]);
  free_rd_atomic_resource(qp, res);
  rxe_advance_resp_resource(qp);
  return res;
}

int __send_packet_with_opcode(
    struct rxe_qp* qp,
    struct irdma_mem* payload,
    struct rxe_pkt_info* req_pkt,
    u8 syndrome,
    u32 psn,
    unsigned opcode_num
) {
  struct rxe_pkt_info new_pkt;
  struct sk_buff *skb;
  struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
  u32 crc = 0;
  int err;
  u32* p;
  int paylen;
  int pad;
  bool atomicack = rxe_opcode[opcode_num].mask & RXE_ATMACK_MASK;

  if(unlikely(!(rxe_opcode[opcode_num].is_ack))) {
      pr_err("Tried to send_ack_packet but specifying a non-ack opcode\n");
      return -EINVAL;
  }

  // allocate packet
  if(payload) {
    pad = (-payload->length) & 0x3;
    paylen = rxe_opcode[opcode_num].length + payload->length + pad + RXE_ICRC_SIZE;
  } else {
    pad = 0;
    paylen = rxe_opcode[opcode_num].length + RXE_ICRC_SIZE;
  }
  skb = rxe->ifc_ops->init_packet(rxe, &qp->pri_av, paylen, &new_pkt);
  if(!skb) return -ENOMEM;
  new_pkt.qp = qp;
  new_pkt.opcode = opcode_num;
  new_pkt.mask = rxe_opcode[opcode_num].mask;
  //new_pkt.irdma_opnum = rxe_opcode[opcode_num].req.irdma_opnum;
    // this is an 'ack' packet, so its req.irdma_opnum is invalid, and
    // new_pkt's irdma_opnum shouldn't ever be touched either
  new_pkt.offset = req_pkt->offset;  // can I change this to rxe_opcode[opcode_num].offset?
  new_pkt.paylen = paylen;

  // fill in bth using the request packet headers
  memcpy(new_pkt.hdr, req_pkt->hdr, req_pkt->offset + RXE_BTH_BYTES);
  // third argument could be new_pkt.offset + RXE_BTH_BYTES
  bth_set_opcode(&new_pkt, opcode_num);
  bth_set_qpn(&new_pkt, qp->attr.dest_qp_num);
  bth_set_pad(&new_pkt, pad);
  bth_set_se(&new_pkt, 0);
  bth_set_psn(&new_pkt, psn);
  bth_set_ack(&new_pkt, 0);  // I guess this field means 'requires ack' and not 'is ack' ???
  new_pkt.psn = psn;

  if(new_pkt.mask & RXE_AETH_MASK) {
      aeth_set_syn(&new_pkt, syndrome);
      aeth_set_msn(&new_pkt, qp->resp.msn);
  }
  if(new_pkt.mask & RXE_ATMACK_MASK) {
      atmack_set_orig(&new_pkt, qp->resp.atomic_orig);
  }

  err = rxe->ifc_ops->prepare(rxe, &new_pkt, skb, &crc);
  if(err) {
      kfree_skb(skb);
      return -ENOMEM;
  }

  if(payload) {
    err = rxe_mem_copy(payload->mr, payload->va, payload_addr(&new_pkt), payload->length, from_mem_obj, &crc);
    if(err) pr_err("Failed copying memory\n");  // but for some reason, keep going
    p = payload_addr(&new_pkt) + payload->length + bth_pad(&new_pkt);
  } else {
    p = payload_addr(&new_pkt) + bth_pad(&new_pkt);
  }
  *p = ~crc;

  err = __send_packet_raw(qp, &new_pkt, skb, rxe, atomicack);
  if(err) pr_err_ratelimited("Failed sending packet with opcode %s\n", rxe_opcode[opcode_num].name);

  return err;
}

int __send_packet_raw(
    struct rxe_qp* qp,
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
      rxe_add_ref(qp);  // for the new SKB
    } else {
      pr_warn("Could not clone atomic response\n");
      return -ENOMEM;
    }
    res = __get_new_resource(qp);
    memcpy(SKB_TO_PKT(skb), pkt, sizeof(skb->cb));
    res->type = IRDMA_RES_ATOMIC;
    res->atomic.skb = skb;
    res->first_psn = pkt->psn;
    res->last_psn = pkt->psn;
    res->cur_psn = pkt->psn;
  }

  err = rxe_xmit_packet(rxe, qp, pkt, atomicack ? skb_copy : skb);
  if(err) {
    if(atomicack) rxe_drop_ref(qp);
    kfree_skb(atomicack ? skb_copy : skb);
  }
  return err;
}

