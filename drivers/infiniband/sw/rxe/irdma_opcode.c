#include "irdma_opcode.h"
#include "irdma.h"
#include "irdma_funcs.h"
#include <rdma/ib_pack.h>  // rdma_network_hdr, maybe among other things
#include "rxe.h"
#include "rxe_loc.h"

// This file contains definitions of the 'built-in' (pre-existing) RDMA opcodes
// in terms of the IRDMA framework.

// irdma_op_nums
#ifndef IRDMA_OPNUMS
#define IRDMA_OPNUMS
#define IRDMA_ACK 0
#define IRDMA_SEND 1
#define IRDMA_WRITE 2
#define IRDMA_READ 3
#define IRDMA_ATOMIC 4
#endif

// ****************************
// 'Helpers' used farther below
static void build_rdma_network_hdr(union rdma_network_hdr *hdr,
				   struct rxe_pkt_info *pkt)
{
	struct sk_buff *skb = PKT_TO_SKB(pkt);

	memset(hdr, 0, sizeof(*hdr));
	if (skb->protocol == htons(ETH_P_IP))
		memcpy(&hdr->roce4grh, ip_hdr(skb), sizeof(hdr->roce4grh));
	else if (skb->protocol == htons(ETH_P_IPV6))
		memcpy(&hdr->ibgrh, ipv6_hdr(skb), sizeof(hdr->ibgrh));
}

static handle_incoming_status send_data_in(struct irdma_context *ic, void *data_addr,
				     int data_len)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);

	err = copy_data(rxe, ic->qp->pd, IB_ACCESS_LOCAL_WRITE, &ic->qp->resp.wqe->dma,
			data_addr, data_len, to_mem_obj, NULL);
	if (unlikely(err))
		return (err == -ENOSPC) ? ERROR_LENGTH
					: ERROR_MALFORMED_WQE;

	return OK;
}

/* Guarantee atomicity of atomic operations at the machine level. */
static DEFINE_SPINLOCK(atomic_ops_lock);

static void cleanup(struct rxe_qp *qp,
				struct rxe_pkt_info *pkt)
{
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

// ****************************
// handle_incoming funcs
static handle_incoming_status handle_incoming_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // TODO
  return OK;
}

static handle_incoming_status handle_incoming_send(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  handle_incoming_status err;
  if (qp_type(ic->qp) == IB_QPT_UD ||
      qp_type(ic->qp) == IB_QPT_SMI ||
      qp_type(ic->qp) == IB_QPT_GSI) {
      union rdma_network_hdr hdr;

      build_rdma_network_hdr(&hdr, pkt);

      err = send_data_in(ic, &hdr, sizeof(hdr));
      if (err) return err;
  }
  return send_data_in(ic, payload_addr(pkt), payload_size(pkt));
}

static handle_incoming_status handle_incoming_write(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
	int	err;
	int data_len = payload_size(pkt);

	err = rxe_mem_copy(ic->qp->resp.mr, ic->qp->resp.va, payload_addr(pkt),
			   data_len, to_mem_obj, NULL);
	if (err) {
		return ERROR_RKEY_VIOLATION;
	}

	ic->qp->resp.va += data_len;
	ic->qp->resp.resid -= data_len;

	return OK;
}

static handle_incoming_status handle_incoming_read(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
	int mtu = ic->qp->mtu;
    struct irdma_mem payload;
	int opcode;
	struct resp_res *res = ic->qp->resp.res;

    /* For RDMA Read we can increment the msn now. See C9-148. */
    ic->qp->resp.msn++;

    // If res is not NULL, then we have a current RDMA request being processed or replayed.
	if (!res) {
		// This is the first time we process that request. Get a resource
        res = get_new_resource(ic);
		res->type	    	= IRDMA_READ;
		res->read.va		= ic->qp->resp.va;
		res->read.va_org	= ic->qp->resp.va;
		res->first_psn		= pkt->psn;
		if (reth_len(pkt)) {
			res->last_psn	= (pkt->psn +
					   (reth_len(pkt) + mtu - 1) /
					   mtu - 1) & BTH_PSN_MASK;
		} else {
			res->last_psn	= res->first_psn;
		}
		res->cur_psn		= pkt->psn;
		res->read.resid		= ic->qp->resp.resid;
		res->read.length	= ic->qp->resp.resid;
		res->read.rkey		= ic->qp->resp.rkey;

		/* note res inherits the reference to mr from qp */
		res->read.mr		= ic->qp->resp.mr;
		ic->qp->resp.mr		= NULL;

		ic->qp->resp.res		= res;
		res->state		= rdatm_res_state_new;
	}

	if (res->state == rdatm_res_state_new) {
		if (res->read.resid <= mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	} else {
		if (res->read.resid > mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	}

	res->state = rdatm_res_state_next;

    payload.mr = res->read.mr;
    payload.va = res->read.va;
	payload.length = min_t(int, res->read.resid, mtu);

    if(send_packet(ic, opcode, &payload, pkt, AETH_ACK_UNLIMITED, res->cur_psn)) return ERROR_RNR;

	res->read.va += payload.length;
	res->read.resid -= payload.length;
	res->cur_psn = (res->cur_psn + 1) & BTH_PSN_MASK;

	if (res->read.resid > 0) {
		return DONE;
	} else {
		ic->qp->resp.res = NULL;
		ic->qp->resp.opcode = -1;
		if (psn_compare(res->cur_psn, ic->qp->resp.psn) >= 0)
			ic->qp->resp.psn = res->cur_psn;
		cleanup(ic->qp, pkt);
        return DONE;
	}
}

static handle_incoming_status handle_incoming_atomic(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
	u64 iova = atmeth_va(pkt);
	u64 *vaddr;
	struct rxe_mem *mr = ic->qp->resp.mr;

	if (mr->state != RXE_MEM_STATE_VALID) {
		return ERROR_RKEY_VIOLATION;
	}

	vaddr = iova_to_vaddr(mr, iova, sizeof(u64));

	/* check vaddr is 8 bytes aligned. */
	if (!vaddr || (uintptr_t)vaddr & 7) {
		return ERROR_MISALIGNED_ATOMIC;
	}

	spin_lock_bh(&atomic_ops_lock);

	ic->qp->resp.atomic_orig = *vaddr;

	if (pkt->opcode == IB_OPCODE_RC_COMPARE_SWAP ||
	    pkt->opcode == IB_OPCODE_RD_COMPARE_SWAP) {
		if (*vaddr == atmeth_comp(pkt))
			*vaddr = atmeth_swap_add(pkt);
	} else {
		*vaddr += atmeth_swap_add(pkt);
	}

	spin_unlock_bh(&atomic_ops_lock);

	return OK;
}

// ****************************
// handle_duplicate funcs
static handle_duplicate_status handle_duplicate_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // TODO
  return HANDLED;
}

static handle_duplicate_status handle_duplicate_sendorwrite(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // Ack again and cleanup. C9-105.
  if(bth_ack(pkt)) send_packet(ic, IB_OPCODE_RC_ACKNOWLEDGE, NULL, pkt, AETH_ACK_UNLIMITED, (ic->qp->resp.psn-1) & BTH_PSN_MASK);
  return HANDLED;
}

static handle_duplicate_status handle_duplicate_read(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  struct resp_res *res = get_existing_resource(ic, pkt->psn);
  if(!res) {
    // Resource not found, Class D error.  Drop the request.
    return HANDLED;
  } else {
    // Ensure this new request is the same as the previous one or a subset of it.
    u64 iova = reth_va(pkt);
    u32 resid = reth_len(pkt);
    if(iova < res->read.va_org ||
        resid > res->read.length ||
        (iova + resid) > (res->read.va_org + res->read.length)) {
      return HANDLED;
    }

    if(reth_rkey(pkt) != res->read.rkey) return HANDLED;
    res->cur_psn = pkt->psn;
    res->state = (pkt->psn == res->first_psn) ? rdatm_res_state_new : rdatm_res_state_replay;

    // Reset the resource, except length.
    res->read.va_org = iova;
    res->read.va = iova;
    res->read.resid = resid;

    // Replay the RDMA read reply.
    ic->qp->resp.res = res;
    return REPROCESS;
  }
}

static handle_duplicate_status handle_duplicate_atomic(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // Find the operation in our list of responder resources.
  struct resp_res *res = get_existing_resource(ic, pkt->psn);
  if(!res) {
    // Resource not found, Class D error.  Drop the request.
    return HANDLED;
  } else {
    send_packet_raw(ic, pkt, res->atomic.skb, to_rdev(ic->qp->ibqp.device), true);
    return HANDLED;
  }
}

// ****************************
// register irdma_ops and rxe_opcodes
register_opcode_status irdma_init_opcodes(void) {
  register_opcode_status st;
#define WITH_CHECK(expr) \
  st = expr; \
  if(st) return st;

  WITH_CHECK(register_irdma_op(IRDMA_ACK, "IRDMA_ACK",
        &handle_incoming_ack, &handle_duplicate_ack, true))
  WITH_CHECK(register_irdma_op(IRDMA_SEND, "IRDMA_SEND",
        &handle_incoming_send, &handle_duplicate_sendorwrite, false))
  WITH_CHECK(register_irdma_op(IRDMA_WRITE, "IRDMA_WRITE",
        &handle_incoming_write, &handle_duplicate_sendorwrite, false))
  WITH_CHECK(register_irdma_op(IRDMA_READ, "IRDMA_READ",
        &handle_incoming_read, &handle_duplicate_read, false))
  WITH_CHECK(register_irdma_op(IRDMA_ATOMIC, "IRDMA_ATOMIC",
        &handle_incoming_atomic, &handle_duplicate_atomic, false))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RC_SEND_FIRST,
      IB_OPCODE_RC_SEND_MIDDLE,
      IB_OPCODE_RC_SEND_LAST,
      IB_OPCODE_RC_SEND_ONLY,
      "IB_OPCODE_RC_SEND",
      /*.irdma_op_num    = */ IRDMA_SEND,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ BOTH,
                              IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE,
                              IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE,
      /*.requiresReceive = */ true,
      /*.postComplete    = */ true,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RC_RDMA_WRITE_FIRST,
      IB_OPCODE_RC_RDMA_WRITE_MIDDLE,
      IB_OPCODE_RC_RDMA_WRITE_LAST,
      IB_OPCODE_RC_RDMA_WRITE_ONLY,
      "IB_OPCODE_RC_RDMA_WRITE",
      /*.irdma_op_num    = */ IRDMA_WRITE,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RC_RDMA_READ_REQUEST,
      "IB_OPCODE_RC_RDMA_READ_REQUEST",
      /*.irdma_op_num    = */ IRDMA_READ,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ true
  ))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
      "IB_OPCODE_RC_RDMA_READ_RESPONSE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RC_ACKNOWLEDGE,
      "IB_OPCODE_RC_ACKNOWLEDGE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
      "IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ true,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RC_COMPARE_SWAP,
      "IB_OPCODE_RC_COMPARE_SWAP",
      /*.irdma_op_num    = */ IRDMA_ATOMIC,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RC_FETCH_ADD,
      "IB_OPCODE_RC_FETCH_ADD",
      /*.irdma_op_num    = */ IRDMA_ATOMIC,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))

  /* UC */
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_UC_SEND_FIRST,
      IB_OPCODE_UC_SEND_MIDDLE,
      IB_OPCODE_UC_SEND_LAST,
      IB_OPCODE_UC_SEND_ONLY,
      "IB_OPCODE_UC_SEND",
      /*.irdma_op_num    = */ IRDMA_SEND,
      /*.qpt             = */ IB_QPT_UC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ true,
      /*.postComplete    = */ true,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_UC_RDMA_WRITE_FIRST,
      IB_OPCODE_UC_RDMA_WRITE_MIDDLE,
      IB_OPCODE_UC_RDMA_WRITE_LAST,
      IB_OPCODE_UC_RDMA_WRITE_ONLY,
      "IB_OPCODE_UC_RDMA_WRITE",
      /*.irdma_op_num    = */ IRDMA_WRITE,
      /*.qpt             = */ IB_QPT_UC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))

  /* UD */
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_UD_SEND_ONLY,
      "IB_OPCODE_UD_SEND_ONLY",
      /*.irdma_op_num    = */ IRDMA_SEND,
      /*.qpt             = */ IB_QPT_UD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ true,
      /*.postComplete    = */ true,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE,
      "IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE",
      /*.irdma_op_num    = */ IRDMA_SEND,
      /*.qpt             = */ IB_QPT_UD,
      /*.immdt           = */ true,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ true,
      /*.postComplete    = */ true,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))

  /* RD */
  // The existing code declares these opcodes for an "RD" qp type
  // (and clearly, the IB_OPCODE_RD_ macros do exist)
  // but IB_QPT_RD is not a valid qpt
  // and it appears these opcodes are probably never used
  // so for the moment I will leave them commented out
#if 0
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RD_SEND_FIRST,
      IB_OPCODE_RD_SEND_MIDDLE,
      IB_OPCODE_RD_SEND_LAST,
      IB_OPCODE_RD_SEND_ONLY,
      "IB_OPCODE_RD_SEND",
      /*.irdma_op_num    = */ IRDMA_SEND,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ true,
      /*.postComplete    = */ true,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RD_RDMA_WRITE_FIRST,
      IB_OPCODE_RD_RDMA_WRITE_MIDDLE,
      IB_OPCODE_RD_RDMA_WRITE_LAST,
      IB_OPCODE_RD_RDMA_WRITE_ONLY,
      "IB_OPCODE_RD_RDMA_WRITE",
      /*.irdma_op_num    = */ IRDMA_WRITE,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RD_RDMA_READ_REQUEST,
      "IB_OPCODE_RD_RDMA_READ_REQUEST",
      /*.irdma_op_num    = */ IRDMA_READ,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_opcode_series(
      IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY,
      "IB_OPCODE_RD_RDMA_READ_RESPONSE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RD_ACKNOWLEDGE,
      "IB_OPCODE_RD_ACKNOWLEDGE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE,
      "IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE",
      /*.irdma_op_num    = */ IRDMA_ACK,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ true,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RD_COMPARE_SWAP,
      "IB_OPCODE_RD_COMPARE_SWAP",
      /*.irdma_op_num    = */ IRDMA_ATOMIC,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
  WITH_CHECK(register_single_opcode(
      IB_OPCODE_RD_FETCH_ADD,
      "IB_OPCODE_RD_FETCH_ADD",
      /*.irdma_op_num    = */ IRDMA_ATOMIC,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.postComplete    = */ false,
      /*.atomicack       = */ false,
      /*.sched_priority  = */ false
  ))
#endif  // if 0

  return st;
}
