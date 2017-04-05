#include "irdma_helpers.h"
#include "rxe_loc.h"

struct rxe_mem* __get_mem(struct rxe_qp* qp, struct rxe_pkt_info* pkt, u32 rkey, u64 va, u32 resid, int access) {
  struct rxe_mem* mem = lookup_mem(qp->pd, access, rkey, lookup_remote);
  if(!mem) goto err1;
  if(unlikely(mem->state == RXE_MEM_STATE_FREE)) goto err1;
  if(mem_check_range(mem, va, resid)) goto err2;
  return mem;
err2:
  rxe_drop_ref(mem);
err1:
  return NULL;
}

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

int __continue_sending_ack_series(struct rxe_qp* qp, struct rxe_pkt_info* req_pkt) {
    int mtu = qp->mtu;
    struct irdma_mem payload;
    struct resp_res *res = qp->resp.res;
    struct rxe_wr_opcode_info* wr_info = &rxe_wr_opcode_info[rxe_opcode[req_pkt->opcode].req.wr_opcode_num];
    struct rxe_opcode_group ack_opcode_group = wr_info->std.ack_opcode_group;
    int opcode;
    int err;

	if (res->state == rdatm_res_state_new) {
		if (res->read.resid <= mtu)
			opcode = ack_opcode_group.opcode_set.only_opcode_num;
		else
			opcode = ack_opcode_group.opcode_set.start_opcode_num;
	} else {
		if (res->read.resid > mtu)
			opcode = ack_opcode_group.opcode_set.middle_opcode_num;
		else
			opcode = ack_opcode_group.opcode_set.end_opcode_num;
	}

	res->state = rdatm_res_state_next;

    payload.mr = res->read.mr;
    payload.va = res->read.va;
	payload.length = min_t(int, res->read.resid, mtu);
    err = __send_packet_with_opcode(qp, &payload, req_pkt, res->read.aeth_syndrome, res->cur_psn, opcode);
    if(err) return err;

	res->read.va += payload.length;
	res->read.resid -= payload.length;
	res->cur_psn = (res->cur_psn + 1) & BTH_PSN_MASK;
	if (res->read.resid > 0) {
		return 0;
	} else {
		qp->resp.res = NULL;
		qp->resp.opcode = -1;
		if (psn_compare(res->cur_psn, qp->resp.psn) >= 0)
			qp->resp.psn = res->cur_psn;
		__cleanup(qp, req_pkt);
        return 0;
	}
}

