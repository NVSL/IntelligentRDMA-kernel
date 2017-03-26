/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"
#include "rxe_queue.h"

#include "irdma_funcs.h"  // eventually this dependency should be removed,
                          // either because code depending on it is moved to
                          // irdma_opcode.c, or because irdma_opcode.c is
                          // merged with this file

enum resp_states {
	RESPST_NONE,
	RESPST_GET_REQ,
	RESPST_CHK_PSN,
	RESPST_CHK_OP_SEQ,
	RESPST_CHK_OP_VALID,
	RESPST_CHK_RESOURCE,
	RESPST_CHK_LENGTH,
	RESPST_CHK_RKEY,
	RESPST_EXECUTE,
	RESPST_COMPLETE,
	RESPST_ACKNOWLEDGE,
	RESPST_CLEANUP,
	RESPST_DUPLICATE_REQUEST,
	RESPST_ERR_UNSUPPORTED_OPCODE,
	RESPST_ERR_PSN_OUT_OF_SEQ,
	RESPST_ERR_MISSING_OPCODE_FIRST,
	RESPST_ERR_MISSING_OPCODE_LAST_C,
	RESPST_ERR_MISSING_OPCODE_LAST_D1E,
	RESPST_ERR_RNR,
	RESPST_ERR_RKEY_VIOLATION,
	RESPST_ERR_LENGTH,
	RESPST_ERR_CQ_OVERFLOW,
	RESPST_ERROR,
	RESPST_RESET,
	RESPST_DONE,
	RESPST_EXIT,
};

static char *resp_state_name[] = {
	[RESPST_NONE]				= "NONE",
	[RESPST_GET_REQ]			= "GET_REQ",
	[RESPST_CHK_PSN]			= "CHK_PSN",
	[RESPST_CHK_OP_SEQ]			= "CHK_OP_SEQ",
	[RESPST_CHK_OP_VALID]			= "CHK_OP_VALID",
	[RESPST_CHK_RESOURCE]			= "CHK_RESOURCE",
	[RESPST_CHK_LENGTH]			= "CHK_LENGTH",
	[RESPST_CHK_RKEY]			= "CHK_RKEY",
	[RESPST_EXECUTE]			= "EXECUTE",
	[RESPST_COMPLETE]			= "COMPLETE",
	[RESPST_ACKNOWLEDGE]			= "ACKNOWLEDGE",
	[RESPST_CLEANUP]			= "CLEANUP",
	[RESPST_DUPLICATE_REQUEST]		= "DUPLICATE_REQUEST",
	[RESPST_ERR_UNSUPPORTED_OPCODE]		= "ERR_UNSUPPORTED_OPCODE",
	[RESPST_ERR_PSN_OUT_OF_SEQ]		= "ERR_PSN_OUT_OF_SEQ",
	[RESPST_ERR_MISSING_OPCODE_FIRST]	= "ERR_MISSING_OPCODE_FIRST",
	[RESPST_ERR_MISSING_OPCODE_LAST_C]	= "ERR_MISSING_OPCODE_LAST_C",
	[RESPST_ERR_MISSING_OPCODE_LAST_D1E]	= "ERR_MISSING_OPCODE_LAST_D1E",
	[RESPST_ERR_RNR]			= "ERR_RNR",
	[RESPST_ERR_RKEY_VIOLATION]		= "ERR_RKEY_VIOLATION",
	[RESPST_ERR_LENGTH]			= "ERR_LENGTH",
	[RESPST_ERR_CQ_OVERFLOW]		= "ERR_CQ_OVERFLOW",
	[RESPST_ERROR]				= "ERROR",
	[RESPST_RESET]				= "RESET",
	[RESPST_DONE]				= "DONE",
	[RESPST_EXIT]				= "EXIT",
};

/* rxe_recv calls here to add a request packet to the input queue */
void rxe_resp_queue_pkt(struct rxe_dev *rxe, struct rxe_qp *qp,
			struct sk_buff *skb)
{
	int must_sched;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

	skb_queue_tail(&qp->req_pkts, skb);

	must_sched = (rxe_opcode[pkt->opcode].mask & IRDMA_SCHED_PRIORITY_MASK) ||
			(skb_queue_len(&qp->req_pkts) > 1);

	rxe_run_task(&qp->resp.task, must_sched);
}

static inline enum resp_states get_req(struct rxe_qp *qp,
				       struct rxe_pkt_info **pkt_p)
{
	struct sk_buff *skb;

	if (qp->resp.state == QP_STATE_ERROR) {
		skb = skb_dequeue(&qp->req_pkts);
		if (skb) {
			/* drain request packet queue */
			rxe_drop_ref(qp);
			kfree_skb(skb);
			return RESPST_GET_REQ;
		}

		/* go drain recv wr queue */
		return RESPST_CHK_RESOURCE;
	}

	skb = skb_peek(&qp->req_pkts);
	if (!skb)
		return RESPST_EXIT;

	*pkt_p = SKB_TO_PKT(skb);

	if(qp->resp.res) {
		struct rxe_pkt_info* pkt = *pkt_p;
		struct irdma_context ic = { qp };
		handle_incoming_status hs = rxe_opcode[pkt->opcode].req.handle_incoming(&ic, pkt);
        switch(hs) {
          case INCOMING_ERROR_LENGTH: return RESPST_ERR_LENGTH;
          case INCOMING_ERROR_RKEY_VIOLATION: return RESPST_ERR_RKEY_VIOLATION;
          case INCOMING_ERROR_RNR: return RESPST_ERR_RNR;
          case INCOMING_ERROR_HANDLED: return RESPST_COMPLETE;
          case INCOMING_DONE: return RESPST_DONE;
          case INCOMING_OK:
            // In the existing code, this handle_incoming call is only ever
            // handle_incoming_read, and that handler should never return INCOMING_OK
            pr_warn("rxe_resp: Not sure what to do here\n");
            break;
          default: /* Unreachable */ WARN_ON(1);
        }
	}

	return RESPST_CHK_PSN;
}

static enum resp_states check_psn(struct rxe_qp *qp,
				  struct rxe_pkt_info *pkt)
{
	int diff = psn_compare(pkt->psn, qp->resp.psn);

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (diff > 0) {
			if (qp->resp.sent_psn_nak)
				return RESPST_CLEANUP;

			qp->resp.sent_psn_nak = 1;
			return RESPST_ERR_PSN_OUT_OF_SEQ;

		} else if (diff < 0) {
			return RESPST_DUPLICATE_REQUEST;
		}

		if (qp->resp.sent_psn_nak)
			qp->resp.sent_psn_nak = 0;

		break;

	case IB_QPT_UC:
		if (qp->resp.drop_msg || diff != 0) {
			if (pkt->mask & RXE_START_MASK) {
				qp->resp.drop_msg = 0;
				return RESPST_CHK_OP_SEQ;
			}

			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	default:
		break;
	}

	return RESPST_CHK_OP_SEQ;
}

static enum resp_states check_op_seq(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
    unsigned int resp_mask = rxe_opcode[qp->resp.opcode].mask;
    unsigned int this_mask = pkt->mask;
    unsigned resp_series_id, this_series_id;
    if(!(resp_mask & RXE_END_MASK)) {
      // In the middle of an operation
      if(this_mask & RXE_START_MASK) {
        // Can't start new operation
        switch(qp_type(qp)) {
          case IB_QPT_RC: return RESPST_ERR_MISSING_OPCODE_LAST_C;
          case IB_QPT_UC: return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
          default:
            // Existing code never has this case, since all other QPTs
            // do not have existing opcodes with RXE_END_MASK unset
            // Provisionally, we'll handle this as UC does
            return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
        }
      }
      resp_series_id = rxe_opcode[qp->resp.opcode].series_id;
      this_series_id = rxe_opcode[pkt->opcode].series_id;
      if(resp_series_id != this_series_id) {
        // Can't switch series
        switch(qp_type(qp)) {
          case IB_QPT_RC: return RESPST_ERR_MISSING_OPCODE_LAST_C;
          case IB_QPT_UC: return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
          default:
            // Existing code never has this case, since all other QPTs
            // do not have existing opcodes with RXE_END_MASK unset
            // Provisionally, we'll handle this as UC does
            return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
        }
      }
    } else {
      // Not in the middle of an operation, expecting a START opcode
      // (note that single/ONLY opcodes also have RXE_START_MASK set)
      if(!(this_mask & RXE_START_MASK)) {
        switch(qp_type(qp)) {
          case IB_QPT_RC: return RESPST_ERR_MISSING_OPCODE_FIRST;
          case IB_QPT_UC:
            qp->resp.drop_msg = 1;
            return RESPST_CLEANUP;
          default:
            // Existing code never has this case, since for all other QPTs,
            // all existing opcodes have RXE_START_MASK set
            // Provisionally, we'll handle this as UC does
            qp->resp.drop_msg = 1;
            return RESPST_CLEANUP;
        }
      }
    }
    // passed all necessary checks
    return RESPST_CHK_OP_VALID;
}

static enum resp_states check_op_valid(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
    unsigned char have_perms = qp->attr.qp_access_flags;
    unsigned char need_perms = rxe_opcode[pkt->opcode].req.perms;
    if((need_perms & have_perms) != need_perms) {
      // missing required perms
      if(qp_type(qp) == IB_QPT_RC) {
        return RESPST_ERR_UNSUPPORTED_OPCODE;
      } else if(qp_type(qp) == IB_QPT_UC) {
        qp->resp.drop_msg = 1;
        return RESPST_CLEANUP;
      } else {
        // do nothing
        // Note this case unreachable in existing code - only RC and UC ops have required perms
      }
    }

	return RESPST_CHK_RESOURCE;
}

static enum resp_states get_srq_wqe(struct rxe_qp *qp)
{
	struct rxe_srq *srq = qp->srq;
	struct rxe_queue *q = srq->rq.queue;
	struct rxe_recv_wqe *wqe;
	struct ib_event ev;

	if (srq->error)
		return RESPST_ERR_RNR;

	spin_lock_bh(&srq->rq.consumer_lock);

	wqe = queue_head(q);
	if (!wqe) {
		spin_unlock_bh(&srq->rq.consumer_lock);
		return RESPST_ERR_RNR;
	}

	/* note kernel and user space recv wqes have same size */
	memcpy(&qp->resp.srq_wqe, wqe, sizeof(qp->resp.srq_wqe));

	qp->resp.wqe = &qp->resp.srq_wqe.wqe;
	advance_consumer(q);

	if (srq->limit && srq->ibsrq.event_handler &&
	    (queue_count(q) < srq->limit)) {
		srq->limit = 0;
		goto event;
	}

	spin_unlock_bh(&srq->rq.consumer_lock);
	return RESPST_CHK_LENGTH;

event:
	spin_unlock_bh(&srq->rq.consumer_lock);
	ev.device = qp->ibqp.device;
	ev.element.srq = qp->ibqp.srq;
	ev.event = IB_EVENT_SRQ_LIMIT_REACHED;
	srq->ibsrq.event_handler(&ev, srq->ibsrq.srq_context);
	return RESPST_CHK_LENGTH;
}

static enum resp_states check_resource(struct rxe_qp *qp,
				       struct rxe_pkt_info *pkt)
{
	struct rxe_srq *srq = qp->srq;

	if (qp->resp.state == QP_STATE_ERROR) {
		if (qp->resp.wqe) {
			qp->resp.status = IB_WC_WR_FLUSH_ERR;
			return RESPST_COMPLETE;
		} else if (!srq) {
			qp->resp.wqe = queue_head(qp->rq.queue);
			if (qp->resp.wqe) {
				qp->resp.status = IB_WC_WR_FLUSH_ERR;
				return RESPST_COMPLETE;
			} else {
				return RESPST_EXIT;
			}
		} else {
			return RESPST_EXIT;
		}
	}

	if (rxe_opcode[pkt->opcode].mask & IRDMA_RES_MASK) {
		/* it is the requesters job to not send
		 * too many read/atomic ops, we just
		 * recycle the responder resource queue
		 */
        // CD note: It appears the above comment has nothing at all to do
        //   with the code here.  Rather, the code seems only to be ensuring
        //   that rd_atomic resources have been allocated; it doesn't check
        //   anything about how many are in use
		if (likely(qp->attr.max_dest_rd_atomic > 0)) {
			return RESPST_CHK_LENGTH;
        } else {
            struct irdma_context ic = { qp };
			do_class_ac_error(&ic, AETH_NAK_INVALID_REQ,
					  IB_WC_REM_INV_REQ_ERR);
            return RESPST_COMPLETE;
        }
	}

	if (pkt->mask & RXE_RWR_MASK) {
		if (srq)
			return get_srq_wqe(qp);

		qp->resp.wqe = queue_head(qp->rq.queue);
		return (qp->resp.wqe) ? RESPST_CHK_LENGTH : RESPST_ERR_RNR;
	}

	return RESPST_CHK_LENGTH;
}

static enum resp_states check_length(struct rxe_qp *qp,
				     struct rxe_pkt_info *pkt)
{
	switch (qp_type(qp)) {
	case IB_QPT_RC:
		return RESPST_CHK_RKEY;

	case IB_QPT_UC:
		return RESPST_CHK_RKEY;

	default:
		return RESPST_CHK_RKEY;
	}
}

static enum resp_states check_rkey(struct rxe_qp *qp,
				   struct rxe_pkt_info *pkt)
{
	struct rxe_mem *mem;
	u64 va;
	u32 rkey;
	u32 resid;
	u32 pktlen;
	int mtu = qp->mtu;
	enum resp_states state;
	int access = rxe_opcode[pkt->opcode].req.perms;
    if(!access) return RESPST_EXECUTE;
      // If you have no required permissions then you don't get to perform
      // any of the actions in the rest of this function

	if (access & IRDMA_PERM_READ || access & IRDMA_PERM_WRITE) {
		if (pkt->mask & RXE_RETH_MASK) {
			qp->resp.va = reth_va(pkt);
			qp->resp.rkey = reth_rkey(pkt);
			qp->resp.resid = reth_len(pkt);
		}
	} else if (access & IRDMA_PERM_ATOMIC) {
      // the 'else' in this seems to assume that we never have both
      // ATOMIC and READ/WRITE.  This is true in existing code.
      // In fact, I think that more than just this will break if this
      // doesn't hold (see e.g. struct rxe_send_wr if I recall correctly)
		qp->resp.va = atmeth_va(pkt);
		qp->resp.rkey = atmeth_rkey(pkt);
		qp->resp.resid = sizeof(u64);
	}

	/* A zero-byte op is not required to set an addr or rkey. */
	if ( (pkt->mask & RXE_RETH_MASK) && reth_len(pkt) == 0 ) {
		return RESPST_EXECUTE;
	}

	va	= qp->resp.va;
	rkey	= qp->resp.rkey;
	resid	= qp->resp.resid;
	pktlen	= payload_size(pkt);

	mem = lookup_mem(qp->pd, access, rkey, lookup_remote);
	if (!mem) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err1;
	}

	if (unlikely(mem->state == RXE_MEM_STATE_FREE)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err1;
	}

	if (mem_check_range(mem, va, resid)) {
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err2;
	}

	if (access & IRDMA_PERM_WRITE)	 {
		if (resid > mtu) {
			if (pktlen != mtu || bth_pad(pkt)) {
				state = RESPST_ERR_LENGTH;
				goto err2;
			}

			qp->resp.resid = mtu;
		} else {
			if (pktlen != resid) {
				state = RESPST_ERR_LENGTH;
				goto err2;
			}
			if ((bth_pad(pkt) != (0x3 & (-resid)))) {
				/* This case may not be exactly that
				 * but nothing else fits.
				 */
				state = RESPST_ERR_LENGTH;
				goto err2;
			}
		}
	}

	WARN_ON(qp->resp.mr);

	qp->resp.mr = mem;
	return RESPST_EXECUTE;

err2:
	rxe_drop_ref(mem);
err1:
	return state;
}

/* Executes a new request. A retried request never reach that function (send
 * and writes are discarded, and reads and atomics are retried elsewhere.
 */
static enum resp_states execute(struct rxe_qp *qp, struct rxe_pkt_info *pkt)
{
	struct irdma_context ic = { qp };
	handle_incoming_status hs = rxe_opcode[pkt->opcode].req.handle_incoming(&ic, pkt);
    switch(hs) {
      case INCOMING_ERROR_LENGTH: return RESPST_ERR_LENGTH;
      case INCOMING_ERROR_RKEY_VIOLATION: return RESPST_ERR_RKEY_VIOLATION;
      case INCOMING_ERROR_RNR: return RESPST_ERR_RNR;
      case INCOMING_ERROR_HANDLED: return RESPST_COMPLETE;
      case INCOMING_DONE: return RESPST_DONE;
      case INCOMING_OK: break;
      default: /* Unreachable */ WARN_ON(1);
    }

	/* We successfully processed this new request. */
	qp->resp.msn++;

	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;

	qp->resp.opcode = pkt->opcode;
	qp->resp.status = IB_WC_SUCCESS;

	if (pkt->mask & RXE_COMP_MASK)
		return RESPST_COMPLETE;
	else if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}

static enum resp_states do_complete(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	struct rxe_cqe cqe;
	struct ib_wc *wc = &cqe.ibwc;
	struct ib_uverbs_wc *uwc = &cqe.uibwc;
	struct rxe_recv_wqe *wqe = qp->resp.wqe;

	if (unlikely(!wqe))
		return RESPST_CLEANUP;

	memset(&cqe, 0, sizeof(cqe));

	wc->wr_id		= wqe->wr_id;
	wc->status		= qp->resp.status;
	wc->qp			= &qp->ibqp;

	/* fields after status are not required for errors */
	if (wc->status == IB_WC_SUCCESS) {
		wc->opcode = rxe_wr_opcode_info[rxe_opcode[pkt->opcode].req.wr_opcode_num].std.receiver_wc_opcode;
		wc->vendor_err = 0;
		wc->byte_len = wqe->dma.length - wqe->dma.resid;

		/* fields after byte_len are different between kernel and user
		 * space
		 */
		if (qp->rcq->is_user) {
			uwc->wc_flags = IB_WC_GRH;

			if (pkt->mask & RXE_IMMDT_MASK) {
				uwc->wc_flags |= IB_WC_WITH_IMM;
				uwc->ex.imm_data =
					(__u32 __force)immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) {
				uwc->wc_flags |= IB_WC_WITH_INVALIDATE;
				uwc->ex.invalidate_rkey = ieth_rkey(pkt);
			}

			uwc->qp_num		= qp->ibqp.qp_num;

			if (pkt->mask & RXE_DETH_MASK)
				uwc->src_qp = deth_sqp(pkt);

			uwc->port_num		= qp->attr.port_num;
		} else {
			struct sk_buff *skb = PKT_TO_SKB(pkt);

			wc->wc_flags = IB_WC_GRH | IB_WC_WITH_NETWORK_HDR_TYPE;
			if (skb->protocol == htons(ETH_P_IP))
				wc->network_hdr_type = RDMA_NETWORK_IPV4;
			else
				wc->network_hdr_type = RDMA_NETWORK_IPV6;

			if (pkt->mask & RXE_IMMDT_MASK) {
				wc->wc_flags |= IB_WC_WITH_IMM;
				wc->ex.imm_data = immdt_imm(pkt);
			}

			if (pkt->mask & RXE_IETH_MASK) {
				struct rxe_dev *rxe = to_rdev(qp->ibqp.device);
				struct rxe_mem *rmr;

				wc->wc_flags |= IB_WC_WITH_INVALIDATE;
				wc->ex.invalidate_rkey = ieth_rkey(pkt);

				rmr = rxe_pool_get_index(&rxe->mr_pool,
							 wc->ex.invalidate_rkey >> 8);
				if (unlikely(!rmr)) {
					pr_err("Bad rkey %#x invalidation\n",
					       wc->ex.invalidate_rkey);
					return RESPST_ERROR;
				}
				rmr->state = RXE_MEM_STATE_FREE;
			}

			wc->qp			= &qp->ibqp;

			if (pkt->mask & RXE_DETH_MASK)
				wc->src_qp = deth_sqp(pkt);

			wc->port_num		= qp->attr.port_num;
		}
	}

	/* have copy for srq and reference for !srq */
	if (!qp->srq)
		advance_consumer(qp->rq.queue);

	qp->resp.wqe = NULL;

	if (rxe_cq_post(qp->rcq, &cqe, pkt ? bth_se(pkt) : 1))
		return RESPST_ERR_CQ_OVERFLOW;

	if (qp->resp.state == QP_STATE_ERROR)
		return RESPST_CHK_RESOURCE;

	if (!pkt)
		return RESPST_DONE;
	else if (qp_type(qp) == IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}

static enum resp_states acknowledge(struct rxe_qp *qp,
				    struct rxe_pkt_info *pkt)
{
	struct irdma_context ic = { qp };

	if (qp_type(qp) != IB_QPT_RC)
		return RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED)
		send_packet(&ic, IB_OPCODE_RC_ACKNOWLEDGE, NULL, pkt, qp->resp.aeth_syndrome, pkt->psn);
    else if (bth_ack(pkt))
        send_packet(&ic, rxe_wr_opcode_info[rxe_opcode[pkt->opcode].req.wr_opcode_num].std.ack_opcode_num,
            NULL, pkt, AETH_ACK_UNLIMITED, pkt->psn);

    return RESPST_CLEANUP;
}

static enum resp_states cleanup(struct rxe_qp *qp,
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

	return RESPST_DONE;
}

static enum resp_states duplicate_request(struct rxe_qp *qp,
					  struct rxe_pkt_info *pkt)
{
	struct irdma_context ic = { qp };

    switch(rxe_opcode[pkt->opcode].req.handle_duplicate(&ic, pkt)) {
      case HANDLED:
        return RESPST_CLEANUP;
      case REPROCESS:
        switch(rxe_opcode[pkt->opcode].req.handle_incoming(&ic, pkt)) {
          case INCOMING_ERROR_LENGTH: return RESPST_ERR_LENGTH;
          case INCOMING_ERROR_RKEY_VIOLATION: return RESPST_ERR_RKEY_VIOLATION;
          case INCOMING_ERROR_RNR: return RESPST_ERR_RNR;
          case INCOMING_ERROR_HANDLED: return RESPST_COMPLETE;
          case INCOMING_DONE: return RESPST_DONE;
          case INCOMING_OK:
            // This never happened in existing code, but I guess just clean up
            pr_warn("rxe_resp: Not sure what to do here\n");
            return RESPST_CLEANUP;
          default: /* Unreachable */ WARN_ON(1); return RESPST_CLEANUP;
        }
      default:
        pr_warn("Missed a case of handle_duplicate_status\n");
        return RESPST_CLEANUP;
    }
}

static enum resp_states do_class_d1e_error(struct rxe_qp *qp)
{
	/* UC */
	if (qp->srq) {
		/* Class E */
		qp->resp.drop_msg = 1;
		if (qp->resp.wqe) {
			qp->resp.status = IB_WC_REM_INV_REQ_ERR;
			return RESPST_COMPLETE;
		} else {
			return RESPST_CLEANUP;
		}
	} else {
		/* Class D1. This packet may be the start of a
		 * new message and could be valid. The previous
		 * message is invalid and ignored. reset the
		 * recv wr to its original state
		 */
		if (qp->resp.wqe) {
			qp->resp.wqe->dma.resid = qp->resp.wqe->dma.length;
			qp->resp.wqe->dma.cur_sge = 0;
			qp->resp.wqe->dma.sge_offset = 0;
			qp->resp.opcode = -1;
		}

		if (qp->resp.mr) {
			rxe_drop_ref(qp->resp.mr);
			qp->resp.mr = NULL;
		}

		return RESPST_CLEANUP;
	}
}

int rxe_responder(void *arg)
{
	struct rxe_qp *qp = (struct rxe_qp *)arg;
	enum resp_states state;
	struct rxe_pkt_info *pkt = NULL;
	int ret = 0;

	struct irdma_context ic = { qp };

	rxe_add_ref(qp);

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;

	if (!qp->valid) {
		ret = -EINVAL;
		goto done;
	}

	switch (qp->resp.state) {
	case QP_STATE_RESET:
		state = RESPST_RESET;
		break;

	default:
		state = RESPST_GET_REQ;
		break;
	}

	while (1) {
		pr_debug("qp#%d state = %s\n", qp_num(qp),
			 resp_state_name[state]);
		switch (state) {
		case RESPST_GET_REQ:
			state = get_req(qp, &pkt);
			break;
		case RESPST_CHK_PSN:
			state = check_psn(qp, pkt);
			break;
		case RESPST_CHK_OP_SEQ:
			state = check_op_seq(qp, pkt);
			break;
		case RESPST_CHK_OP_VALID:
			state = check_op_valid(qp, pkt);
			break;
		case RESPST_CHK_RESOURCE:
			state = check_resource(qp, pkt);
			break;
		case RESPST_CHK_LENGTH:
			state = check_length(qp, pkt);
			break;
		case RESPST_CHK_RKEY:
			state = check_rkey(qp, pkt);
			break;
		case RESPST_EXECUTE:
			state = execute(qp, pkt);
			break;
		case RESPST_COMPLETE:
			state = do_complete(qp, pkt);
			break;
		case RESPST_ACKNOWLEDGE:
			state = acknowledge(qp, pkt);
			break;
		case RESPST_CLEANUP:
			state = cleanup(qp, pkt);
			break;
		case RESPST_DUPLICATE_REQUEST:
			state = duplicate_request(qp, pkt);
			break;
		case RESPST_ERR_PSN_OUT_OF_SEQ:
			/* RC only - Class B. Drop packet. */
			send_packet(&ic, IB_OPCODE_RC_ACKNOWLEDGE, NULL, pkt, AETH_NAK_PSN_SEQ_ERROR, qp->resp.psn);
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_MISSING_OPCODE_FIRST:
		case RESPST_ERR_MISSING_OPCODE_LAST_C:
		case RESPST_ERR_UNSUPPORTED_OPCODE:
			/* RC Only - Class C. */
			do_class_ac_error(&ic, AETH_NAK_INVALID_REQ,
					  IB_WC_REM_INV_REQ_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_MISSING_OPCODE_LAST_D1E:
			state = do_class_d1e_error(qp);
			break;
		case RESPST_ERR_RNR:
			if (qp_type(qp) == IB_QPT_RC) {
				/* RC - class B */
				send_packet(&ic, IB_OPCODE_RC_ACKNOWLEDGE, NULL, pkt,
					AETH_RNR_NAK | (~AETH_TYPE_MASK & qp->attr.min_rnr_timer),
					pkt->psn);
			} else {
				/* UD/UC - class D */
				qp->resp.drop_msg = 1;
			}
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_RKEY_VIOLATION:
			if (qp_type(qp) == IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(&ic, AETH_NAK_REM_ACC_ERR,
						  IB_WC_REM_ACCESS_ERR);
				state = RESPST_COMPLETE;
			} else {
				qp->resp.drop_msg = 1;
				if (qp->srq) {
					/* UC/SRQ Class D */
					qp->resp.status = IB_WC_REM_ACCESS_ERR;
					state = RESPST_COMPLETE;
				} else {
					/* UC/non-SRQ Class E. */
					state = RESPST_CLEANUP;
				}
			}
			break;

		case RESPST_ERR_LENGTH:
			if (qp_type(qp) == IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(&ic, AETH_NAK_INVALID_REQ,
						  IB_WC_REM_INV_REQ_ERR);
				state = RESPST_COMPLETE;
			} else if (qp->srq) {
				/* UC/UD - class E */
				qp->resp.status = IB_WC_REM_INV_REQ_ERR;
				state = RESPST_COMPLETE;
			} else {
				/* UC/UD - class D */
				qp->resp.drop_msg = 1;
				state = RESPST_CLEANUP;
			}
			break;

		case RESPST_ERR_CQ_OVERFLOW:
			/* All - Class G */
			state = RESPST_ERROR;
			break;

		case RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto done;

		case RESPST_EXIT:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto exit;

		case RESPST_RESET: {
			struct sk_buff *skb;

			while ((skb = skb_dequeue(&qp->req_pkts))) {
				rxe_drop_ref(qp);
				kfree_skb(skb);
			}

			while (!qp->srq && qp->rq.queue &&
			       queue_head(qp->rq.queue))
				advance_consumer(qp->rq.queue);

			qp->resp.wqe = NULL;
			goto exit;
		}

		case RESPST_ERROR:
			qp->resp.goto_error = 0;
			pr_warn("qp#%d moved to error state\n", qp_num(qp));
			rxe_qp_error(qp);
			goto exit;

		default:
			WARN_ON(1);
		}
	}

exit:
	ret = -EAGAIN;
done:
	rxe_drop_ref(qp);
	return ret;
}
