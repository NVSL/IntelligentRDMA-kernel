#include "irdma_opcode.h"
#include "irdma.h"
#include "irdma_funcs.h"
#include "irdma_helpers.h"
#include <rdma/ib_pack.h>  // rdma_network_hdr, maybe among other things
#include "rxe.h"
#include "rxe_loc.h"

// This file contains definitions of the 'built-in' (pre-existing) RDMA opcodes
// in terms of the IRDMA framework.

// see notes in irdma.h
#ifndef IRDMA_REQ_OPNUMS
#define IRDMA_REQ_OPNUMS
typedef enum {
  IRDMA_REQ_SEND,
  IRDMA_REQ_WRITE,
  IRDMA_REQ_READ,
  IRDMA_REQ_ATOMIC,
} IRDMA_REQ_OPNUM;
#endif

// Opcode numbers.  Ideally this is the only place they are defined, and outside code
// is completely agnostic to them.
#define IRDMA_WR_CUSTOM (0x10)
#define IRDMA_OPCODE_CUSTOM_REQ (0x18)
#define IRDMA_OPCODE_CUSTOM_ACK (0x19)

// ****************************
// 'Helpers' used farther below
static handle_incoming_status send_data_in(struct irdma_context *ic, void *data_addr,
				     int data_len)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);

	err = copy_data(rxe, ic->qp->pd, IB_ACCESS_LOCAL_WRITE, &ic->qp->resp.wqe->dma,
			data_addr, data_len, to_mem_obj, NULL);
	if (unlikely(err)) {
      if(err == -ENOSPC) {
        return INCOMING_ERROR_LENGTH;
      } else {
        // All queue types, Class A error.
        do_class_ac_error(ic, AETH_NAK_REM_OP_ERR,
            IB_WC_LOC_QP_OP_ERR);
        return INCOMING_ERROR_HANDLED;
      }
    }

	return INCOMING_OK;
}

/* Guarantee atomicity of atomic operations at the machine level. */
static DEFINE_SPINLOCK(atomic_ops_lock);

// ****************************
// handle_incoming funcs for 'req' opcodes
static handle_incoming_status handle_incoming_send(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  handle_incoming_status err;
  if (qp_type(ic->qp) == IB_QPT_UD ||
      qp_type(ic->qp) == IB_QPT_SMI ||
      qp_type(ic->qp) == IB_QPT_GSI) {

      // build rdma network hdr
      union rdma_network_hdr hdr;
      struct sk_buff *skb = PKT_TO_SKB(pkt);

      memset(&hdr, 0, sizeof(hdr));
      if (skb->protocol == htons(ETH_P_IP))
          memcpy(&hdr.roce4grh, ip_hdr(skb), sizeof(hdr.roce4grh));
      else if (skb->protocol == htons(ETH_P_IPV6))
          memcpy(&hdr.ibgrh, ipv6_hdr(skb), sizeof(hdr.ibgrh));

      err = send_data_in(ic, &hdr, sizeof(hdr));
      if (err) return err;
  }
  return send_data_in(ic, payload_addr(pkt), payload_size(pkt));
}

static handle_incoming_status handle_incoming_write(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
	int	err;
	int data_len = payload_size(pkt);
    int mtu = ic->qp->mtu;
    u32 rkey = reth_rkey(pkt);
    u64 va = reth_va(pkt);
    u32 resid = reth_len(pkt);
    u32 pktlen = payload_size(pkt);
    struct rxe_mem* mem = ic->qp->resp.mr;

    if(resid != 0) {
      // a zero-byte write is not required to do these steps
      mem = get_mem(ic, pkt, rkey, va, resid, IB_ACCESS_REMOTE_WRITE);
      if(!mem) return INCOMING_ERROR_RKEY_VIOLATION;

      if(resid > mtu) {
        if(pktlen != mtu || bth_pad(pkt)) goto lengtherr;
      } else {
        if(pktlen != resid) goto lengtherr;
        if((bth_pad(pkt) != (0x3 & (-resid)))) goto lengtherr;
          // "the above case may not be exactly that, but nothing else fits"
      }
      WARN_ON(ic->qp->resp.mr);  // already had a reference to one mr,
                                 // about to get a reference to another
      ic->qp->resp.mr = mem;
    }

	err = rxe_mem_copy(mem, va, payload_addr(pkt),
			   data_len, to_mem_obj, NULL);
	if (err) {
		return INCOMING_ERROR_RKEY_VIOLATION;
        // where does the ref to mem get dropped?
	}

	return INCOMING_OK;

lengtherr:
    rxe_drop_ref(mem);
    return INCOMING_ERROR_LENGTH;
}

static handle_incoming_status handle_incoming_read(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
    struct irdma_mem payload;

    u32 rkey = reth_rkey(pkt);
    u64 va = reth_va(pkt);
    u32 resid = reth_len(pkt);
    struct rxe_mem* mem = ic->qp->resp.mr;

    if(resid != 0) {
      // a zero-byte read is not required to do these steps
      WARN_ON(ic->qp->resp.mr);  // already had a reference to one mr,
                                 // about to get a reference to another
      mem = get_mem(ic, pkt, rkey, va, resid, IB_ACCESS_REMOTE_READ);
      if(!mem) return INCOMING_ERROR_RKEY_VIOLATION;
    }

    // payload inherits the reference to mem (resp.mr) from qp
    payload.mr = mem;
    ic->qp->resp.mr = NULL;
    payload.va = va;
    payload.length = resid;

    // this function inherits the reference to mr, so payload no longer has it
    if(send_ack_packet_or_series(ic, &payload, pkt, AETH_ACK_UNLIMITED, pkt->psn)) return INCOMING_ERROR_RNR;

    return INCOMING_OK;
}

static handle_incoming_status handle_incoming_custom(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
    int raw_payload[] = {5};
    struct irdma_mem payload = {NULL, (u64)(raw_payload), sizeof(int)};
    if(send_ack_packet_or_series(ic, &payload, pkt, AETH_ACK_UNLIMITED, pkt->psn)) return INCOMING_ERROR_RNR;
    return INCOMING_OK;
}

static handle_incoming_status handle_incoming_atomic(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
	struct rxe_mem *mem = ic->qp->resp.mr;

    u32 rkey = atmeth_rkey(pkt);
    u64 va = atmeth_va(pkt);
	u64 *vaddr;
    u32 resid = sizeof(u64);

    if(resid != 0) {
      // a zero-byte atomic op is not required to do these steps
      mem = get_mem(ic, pkt, rkey, va, resid, IB_ACCESS_REMOTE_ATOMIC);
      if(!mem) return INCOMING_ERROR_RKEY_VIOLATION;
      WARN_ON(ic->qp->resp.mr);  // already had a reference to one mr,
                                 // about to get a reference to another
      ic->qp->resp.mr = mem;
    }

	if (mem->state != RXE_MEM_STATE_VALID) {
		return INCOMING_ERROR_RKEY_VIOLATION;
	}

	vaddr = iova_to_vaddr(mem, va, resid);

	/* check vaddr is 8 bytes aligned. */
	if (!vaddr || (uintptr_t)vaddr & 7) {
        // RC only, Class C error
        do_class_ac_error(ic, AETH_NAK_INVALID_REQ,
            IB_WC_REM_INV_REQ_ERR);
		return INCOMING_ERROR_HANDLED;
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

	return INCOMING_OK;
}

// ****************************
// handle_duplicate funcs for 'req' opcodes
static handle_duplicate_status handle_duplicate_sendorwrite(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // Ack again and cleanup. C9-105.
  if(bth_ack(pkt)) send_ack_packet_or_series(ic, NULL, pkt, AETH_ACK_UNLIMITED, (ic->qp->resp.psn-1) & BTH_PSN_MASK);
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

static handle_duplicate_status handle_duplicate_custom(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  pr_warn("Duplicate custom-opcode received\n");
  return HANDLED;
}

static handle_duplicate_status handle_duplicate_atomic(struct irdma_context* ic, struct rxe_pkt_info* pkt) {
  // Find the operation in our list of responder resources.
  struct resp_res *res = get_existing_resource(ic, pkt->psn);
  if(!res) {
    // Resource not found, Class D error.  Drop the request.
    return HANDLED;
  } else {
    resend_packet(ic, pkt, res->atomic.skb, to_rdev(ic->qp->ibqp.device), true);
    return HANDLED;
  }
}

// ****************************
// handle_incoming funcs for 'ack' opcodes
static handle_ack_status handle_incoming_read_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt, struct rxe_send_wqe* wqe) {
  struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);
  int ret;

  ret = copy_data(rxe, ic->qp->pd, IB_ACCESS_LOCAL_WRITE,
          &wqe->dma, payload_addr(pkt),
          payload_size(pkt), to_mem_obj, NULL);
  if (ret) return ACK_ERROR;

  if(wqe->dma.resid == 0 && (pkt->mask & RXE_END_MASK))
    return ACK_COMPLETE;
  else
    return ACK_NEXT;
}

static handle_ack_status handle_incoming_atomic_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt, struct rxe_send_wqe* wqe) {
  struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);
  int ret;

  u64 atomic_orig = atmack_orig(pkt);

  ret = copy_data(rxe, ic->qp->pd, IB_ACCESS_LOCAL_WRITE,
          &wqe->dma, &atomic_orig,
          sizeof(u64), to_mem_obj, NULL);
  if (ret) return ACK_ERROR;

  if(wqe->dma.resid == 0 && (pkt->mask & RXE_END_MASK))
    return ACK_COMPLETE;
  else
    return ACK_NEXT;
}

static handle_ack_status handle_incoming_sendorwrite_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt, struct rxe_send_wqe* wqe) {
  if(wqe->state == wqe_state_pending && wqe->last_psn == pkt->psn)
    return ACK_COMPLETE;
  else
    return ACK_NEXT;
}

static handle_ack_status handle_incoming_custom_ack(struct irdma_context* ic, struct rxe_pkt_info* pkt, struct rxe_send_wqe* wqe) {
  pr_warn("Received value %i in custom ack\n", *(int*)payload_addr(pkt));
  return ACK_COMPLETE;
}

// ****************************
// handle_wr funcs for 'loc' wr_opcodes
static handle_loc_status handle_wr_reg_mr(struct irdma_context* ic, struct rxe_send_wqe* wqe) {
  struct rxe_mem *rmr = to_rmr(wqe->wr.wr.reg.mr);
  rmr->state = RXE_MEM_STATE_VALID;
  rmr->access = wqe->wr.wr.reg.access;
  rmr->lkey = wqe->wr.wr.reg.key;
  rmr->rkey = wqe->wr.wr.reg.key;
  return LOC_OK;

}

static handle_loc_status handle_wr_local_inv(struct irdma_context* ic, struct rxe_send_wqe* wqe) {
  struct rxe_dev *rxe = to_rdev(ic->qp->ibqp.device);
  struct rxe_mem *rmr = rxe_pool_get_index(&rxe->mr_pool, wqe->wr.ex.invalidate_rkey >> 8);
  if (!rmr) {
      pr_err("No mr for key %#x\n", wqe->wr.ex.invalidate_rkey);
      return LOC_ERROR;
  }
  rmr->state = RXE_MEM_STATE_FREE;
  return LOC_OK;
}

// ****************************
// register wr_opcodes, ack opcodes, and req opcodes
register_opcode_status irdma_init_opcodes(void) {
  register_opcode_status st;
  enum ib_qp_type qpts[] = {IB_QPT_RC, IB_QPT_UC, IB_QPT_UD, IB_QPT_SMI, IB_QPT_GSI};
    // (currently we can get away with just passing in contiguous subsets of the above
    // array as 'qpts' for all existing wr_opcodes)

#define WITH_CHECK(expr) \
  st = expr; \
  if(st) { \
    pr_err("Error %d with command " #expr "\n", st); \
    return st; \
  }

  // 'ack' opcodes (note have to do these before wr_opcodes, since
  // register_wr_opcode requires an ack_opcode_num for the wr_opcode)
  WITH_CHECK(register_single_ack_opcode(
      IB_OPCODE_RC_ACKNOWLEDGE,
      "IB_OPCODE_RC_ACKNOWLEDGE",
      /*.handle_incoming  = */ &handle_incoming_sendorwrite_ack,
      /*.atomicack       = */ false
  ))
  WITH_CHECK(register_single_ack_opcode(
      IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE,
      "IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE",
      /*.handle_incoming  = */ &handle_incoming_atomic_ack,
      /*.atomicack       = */ true
  ))
  WITH_CHECK(register_ack_opcode_series(
      IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST,
      IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY,
      "IB_OPCODE_RC_RDMA_READ_RESPONSE",
      /*.handle_incoming  = */ &handle_incoming_read_ack,
      /*.atomicack       = */ false
  ))
  WITH_CHECK(register_single_ack_opcode(
      IRDMA_OPCODE_CUSTOM_ACK,
      "IRDMA_OPCODE_CUSTOM_ACK",
      /*.handle_incoming  = */ &handle_incoming_custom_ack,
      /*.atomicack       = */ false
  ))

  // wr_opcodes
  WITH_CHECK(register_std_wr_opcode(IB_WR_RDMA_WRITE, "IB_WR_RDMA_WRITE",
        /* compatible qpts  */ qpts, 2,
        /* type           = */ WR_WRITE_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ true,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_RDMA_WRITE,
        /* postComplete       = */ false,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_RDMA_WRITE_WITH_IMM, "IB_WR_RDMA_WRITE_WITH_IMM",
        /* compatible qpts  */ qpts, 2,
        /* type           = */ WR_WRITE_MASK,
        /* immdt          = */ true,
        /* invalidate     = */ false,
        /* wr_inline      = */ true,
        /* alwaysEnabl... = */ false,  // or true, doesn't matter
        /* sender_wc_opcode   = */ IB_WC_RDMA_WRITE,
        /* postComplete       = */ true,
        /* receiver_wc_opcode = */ IB_WC_RECV_RDMA_WITH_IMM,
        /* ack_opcode_num = */ IB_OPCODE_RC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_SEND, "IB_WR_SEND",
        /* compatible qpts  */ qpts, 5,
        /* type           = */ WR_SEND_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ true,
        /* alwaysEnabl... = */ true,
        /* sender_wc_opcode   = */ IB_WC_SEND,
        /* postComplete       = */ true,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_SEND_WITH_IMM, "IB_WR_SEND_WITH_IMM",
        /* compatible qpts  */ qpts, 5,
        /* type           = */ WR_SEND_MASK,
        /* immdt          = */ true,
        /* invalidate     = */ false,
        /* wr_inline      = */ true,
        /* alwaysEnabl... = */ true,  // or false, doesn't matter
        /* sender_wc_opcode   = */ IB_WC_SEND,
        /* postComplete       = */ true,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_RDMA_READ, "IB_WR_RDMA_READ",
        /* compatible qpts  */ qpts, 1,
        /* type           = */ WR_READ_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ false,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_RDMA_READ,
        /* postComplete       = */ false,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST))
  WITH_CHECK(register_std_wr_opcode(IB_WR_ATOMIC_CMP_AND_SWP, "IB_WR_ATOMIC_CMP_AND_SWP",
        /* compatible qpts  */ qpts, 1,
        /* type           = */ WR_ATOMIC_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ false,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_COMP_SWAP,
        /* postComplete       = */ false,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_ATOMIC_FETCH_AND_ADD, "IB_WR_ATOMIC_FETCH_AND_ADD",
        /* compatible qpts  */ qpts, 1,
        /* type           = */ WR_ATOMIC_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ false,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_FETCH_ADD,
        /* postComplete       = */ false,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_LSO, "IB_WR_LSO", NULL, 0, 0, false, false, false, false, IB_WC_LSO, false, IB_WC_RECV, 0))  // not supported
  WITH_CHECK(register_std_wr_opcode(IB_WR_SEND_WITH_INV, "IB_WR_SEND_WITH_INV",
        /* compatible qpts  */ qpts, 3,
        /* type           = */ WR_SEND_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ true,
        /* wr_inline      = */ true,
        /* alwaysEnabl... = */ true,
        /* sender_wc_opcode   = */ IB_WC_SEND,
        /* postComplete       = */ true,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_ACKNOWLEDGE))
  WITH_CHECK(register_std_wr_opcode(IB_WR_RDMA_READ_WITH_INV, "IB_WR_RDMA_READ_WITH_INV",
        /* compatible qpts  */ qpts, 1,
        /* type           = */ WR_READ_MASK,
        /* immdt          = */ false,
        /* invalidate     = */ true,
        /* wr_inline      = */ false,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_RDMA_READ,
        /* postComplete       = */ true,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST))
  WITH_CHECK(register_std_wr_opcode(IRDMA_WR_CUSTOM, "IRDMA_WR_CUSTOM",
        /* compatible qpts  */ qpts, 1,
        /* type           = */ WR_READ_MASK,  // TODO not correct at all, wrong behavior in certain places
        /* immdt          = */ false,
        /* invalidate     = */ false,
        /* wr_inline      = */ false,
        /* alwaysEnabl... = */ false,
        /* sender_wc_opcode   = */ IB_WC_RDMA_READ,
        /* postComplete       = */ false,
        /* receiver_wc_opcode = */ IB_WC_RECV,
        /* ack_opcode_num = */ IRDMA_OPCODE_CUSTOM_ACK))
  WITH_CHECK(register_loc_wr_opcode(IB_WR_REG_MR, "IB_WR_REG_MR",
        /* handle_wr      = */ &handle_wr_reg_mr,
        /* wr_inline      = */ false))
  WITH_CHECK(register_loc_wr_opcode(IB_WR_LOCAL_INV, "IB_WR_LOCAL_INV",
        /* handle_wr      = */ &handle_wr_local_inv,
        /* wr_inline      = */ false))

  // 'req' opcodes (note have to do these after wr_opcodes, because we have to
  // reference them against existing wr_opcodes)
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_RC_SEND_FIRST,
      IB_OPCODE_RC_SEND_MIDDLE,
      IB_OPCODE_RC_SEND_LAST,
      IB_OPCODE_RC_SEND_ONLY,
      "IB_OPCODE_RC_SEND",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_send,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_SEND,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE,
                              IB_WR_SEND_WITH_IMM,
      /*.invalidate      = */ BOTH,
                              IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE,
                              IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE,
                              IB_WR_SEND_WITH_INV,
      /*.requiresReceive = */ true,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_RC_RDMA_WRITE_FIRST,
      IB_OPCODE_RC_RDMA_WRITE_MIDDLE,
      IB_OPCODE_RC_RDMA_WRITE_LAST,
      IB_OPCODE_RC_RDMA_WRITE_ONLY,
      "IB_OPCODE_RC_RDMA_WRITE",
      /*.irdma_req_opnum  = */ IRDMA_REQ_WRITE,
      /*.handle_incoming  = */ &handle_incoming_write,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_RDMA_WRITE,
      /*.qpt             = */ IB_QPT_RC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
                              IB_WR_RDMA_WRITE_WITH_IMM,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_WRITE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RC_RDMA_READ_REQUEST,
      "IB_OPCODE_RC_RDMA_READ_REQUEST",
      /*.irdma_req_opnum  = */ IRDMA_REQ_READ,
      /*.handle_incoming  = */ &handle_incoming_read,
      /*.handle_duplicate = */ &handle_duplicate_read,
      /*.wr_opcode_num   = */ IB_WR_RDMA_READ,
      /*.qpt             = */ IB_QPT_RC,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_READ,
      /*.sched_priority  = */ true,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RC_COMPARE_SWAP,
      "IB_OPCODE_RC_COMPARE_SWAP",
      /*.irdma_req_opnum  = */ IRDMA_REQ_ATOMIC,
      /*.handle_incoming  = */ &handle_incoming_atomic,
      /*.handle_duplicate = */ &handle_duplicate_atomic,
      /*.wr_opcode_num   = */ IB_WR_ATOMIC_CMP_AND_SWP,
      /*.qpt             = */ IB_QPT_RC,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_ATOMIC,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ true
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RC_FETCH_ADD,
      "IB_OPCODE_RC_FETCH_ADD",
      /*.irdma_req_opnum  = */ IRDMA_REQ_ATOMIC,
      /*.handle_incoming  = */ &handle_incoming_atomic,
      /*.handle_duplicate = */ &handle_duplicate_atomic,
      /*.wr_opcode_num   = */ IB_WR_ATOMIC_FETCH_AND_ADD,
      /*.qpt             = */ IB_QPT_RC,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_ATOMIC,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IRDMA_OPCODE_CUSTOM_REQ,
      "IRDMA_OPCODE_CUSTOM_REQ",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_custom,
      /*.handle_duplicate = */ &handle_duplicate_custom,
      /*.wr_opcode_num   = */ IRDMA_WR_CUSTOM,
      /*.qpt             = */ IB_QPT_RC,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))

  /* UC */
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_UC_SEND_FIRST,
      IB_OPCODE_UC_SEND_MIDDLE,
      IB_OPCODE_UC_SEND_LAST,
      IB_OPCODE_UC_SEND_ONLY,
      "IB_OPCODE_UC_SEND",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_send,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_SEND,
      /*.qpt             = */ IB_QPT_UC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE,
                              IB_WR_SEND_WITH_IMM,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ true,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_UC_RDMA_WRITE_FIRST,
      IB_OPCODE_UC_RDMA_WRITE_MIDDLE,
      IB_OPCODE_UC_RDMA_WRITE_LAST,
      IB_OPCODE_UC_RDMA_WRITE_ONLY,
      "IB_OPCODE_UC_RDMA_WRITE",
      /*.irdma_req_opnum  = */ IRDMA_REQ_WRITE,
      /*.handle_incoming  = */  &handle_incoming_write,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_RDMA_WRITE,
      /*.qpt             = */ IB_QPT_UC,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
                              IB_WR_RDMA_WRITE_WITH_IMM,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_WRITE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))

  /* UD */
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_UD_SEND_ONLY,
      "IB_OPCODE_UD_SEND_ONLY",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_send,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_SEND,
      /*.qpt             = */ IB_QPT_UD,
      /*.requiresReceive = */ true,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE,
      "IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_send,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_SEND_WITH_IMM,
      /*.qpt             = */ IB_QPT_UD,
      /*.requiresReceive = */ true,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))

  /* RD */
  // The existing code declares these opcodes for an "RD" qp type
  // (and clearly, the IB_OPCODE_RD_ macros do exist)
  // but IB_QPT_RD is not a valid qpt
  // and it appears these opcodes are probably never used
  // so for the moment I will leave them commented out
#if 0
  // 'ack' opcodes
  WITH_CHECK(register_ack_opcode_series(
      IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST,
      IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY,
      "IB_OPCODE_RD_RDMA_READ_RESPONSE",
      /*.handle_incoming  = */ &handle_incoming_read_ack,
      /*.qpt             = */ IB_QPT_RD,
      /*.atomicack       = */ false
  ))
  WITH_CHECK(register_single_ack_opcode(
      IB_OPCODE_RD_ACKNOWLEDGE,
      "IB_OPCODE_RD_ACKNOWLEDGE",
      /*.handle_incoming  = */ &handle_incoming_sendorwrite_ack,
      /*.qpt             = */ IB_QPT_RD,
      /*.atomicack       = */ false
  ))
  WITH_CHECK(register_single_ack_opcode(
      IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE,
      "IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE",
      /*.handle_incoming  = */ &handle_incoming_atomic_ack,
      /*.qpt             = */ IB_QPT_RD,
      /*.atomicack       = */ true
  ))

  // 'req' opcodes
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_RD_SEND_FIRST,
      IB_OPCODE_RD_SEND_MIDDLE,
      IB_OPCODE_RD_SEND_LAST,
      IB_OPCODE_RD_SEND_ONLY,
      "IB_OPCODE_RD_SEND",
      /*.irdma_req_opnum  = */ IRDMA_REQ_SEND,
      /*.handle_incoming  = */ &handle_incoming_send,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_SEND,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE,
                              IB_WR_SEND_WITH_IMM,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ true,
      /*.perms           = */ IRDMA_PERM_NONE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_req_opcode_series(
      IB_OPCODE_RD_RDMA_WRITE_FIRST,
      IB_OPCODE_RD_RDMA_WRITE_MIDDLE,
      IB_OPCODE_RD_RDMA_WRITE_LAST,
      IB_OPCODE_RD_RDMA_WRITE_ONLY,
      "IB_OPCODE_RD_RDMA_WRITE",
      /*.irdma_req_opnum  = */ IRDMA_REQ_WRITE,
      /*.handle_incoming  = */ &handle_incoming_write,
      /*.handle_duplicate = */ &handle_duplicate_sendorwrite,
      /*.wr_opcode_num   = */ IB_WR_RDMA_WRITE,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ BOTH,
                              IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE,
                              IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE,
                              IB_WR_RDMA_WRITE_WITH_IMM,
      /*.invalidate      = */ NO,
                              0,  // ignored
                              0,  // ignored
                              0,  // ignored
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_WRITE,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RD_RDMA_READ_REQUEST,
      "IB_OPCODE_RD_RDMA_READ_REQUEST",
      /*.irdma_req_opnum  = */ IRDMA_REQ_READ,
      /*.handle_incoming  = */ &handle_incoming_read,
      /*.handle_duplicate = */ &handle_duplicate_read,
      /*.wr_opcode_num   = */ IB_WR_RDMA_READ,
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_READ,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RD_COMPARE_SWAP,
      "IB_OPCODE_RD_COMPARE_SWAP",
      /*.irdma_req_opnum  = */ IRDMA_REQ_ATOMIC,
      /*.handle_incoming  = */ &handle_incoming_atomic,
      /*.handle_duplicate = */ &handle_duplicate_atomic,
      /*.wr_opcode_num   = */ 0,  // ignored
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_ATOMIC,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ true
  ))
  WITH_CHECK(register_single_req_opcode(
      IB_OPCODE_RD_FETCH_ADD,
      "IB_OPCODE_RD_FETCH_ADD",
      /*.irdma_req_opnum  = */ IRDMA_REQ_ATOMIC,
      /*.handle_incoming  = */ &handle_incoming_atomic,
      /*.handle_duplicate = */ &handle_duplicate_atomic,
      /*.wr_opcode_num   = */ 0,  // ignored
      /*.qpt             = */ IB_QPT_RD,
      /*.immdt           = */ false,
      /*.invalidate      = */ false,
      /*.requiresReceive = */ false,
      /*.perms           = */ IRDMA_PERM_ATOMIC,
      /*.sched_priority  = */ false,
      /*.comp_swap       = */ false
  ))
#endif  // if 0

  return st;
}
