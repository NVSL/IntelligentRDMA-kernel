#ifndef IRDMA_H
#define IRDMA_H

#include <rdma/ib_pack.h>  // BIT()
#include <rdma/rdma_user_rxe.h>  // rxe_send_wqe

// forward declarations of a few structs we need
struct rxe_pkt_info;  // declared in rxe_hdr.h

void irdma_init(void);

// handle_incoming_status is the return type of the handle_incoming function for a 'req' opcode.
typedef enum {
  INCOMING_OK = 0,  // indicates no error
  INCOMING_ERROR_LENGTH,  // indicates that copy_data returned -ENOSPC
  INCOMING_ERROR_RKEY_VIOLATION,  // explanation TBD, but name seems straightforward
  INCOMING_ERROR_RNR,  // 'receiver not ready' - indicates that a required receive request was not posted
  INCOMING_ERROR_HANDLED,  // indicates that there was an error, but it has already been handled
  INCOMING_DONE,  // indicates we are completely done handling the packet, with no error.
                  // Note that INCOMING_OK should usually be used instead -
                  // with INCOMING_OK, a bunch of bookkeeping is done to
                  // complete the processing of this packet and prepare for the next.
                  // INCOMING_DONE indicates that you've already done all this yourself.
} handle_incoming_status;

// handle_duplicate_status is the return type of the handle_duplicate function for a 'req' opcode.
typedef enum {
  HANDLED,    // duplicate packet has been handled, we're done
  REPROCESS,  // please now reprocess the duplicate packet (with handle_incoming) and proceed from
              //   there based on the return code from handle_incoming, as normal
} handle_duplicate_status;

// handle_ack_status is the return type of the handle_incoming function for an 'ack' opcode.
typedef enum {
  ACK_OK = 0,  // indicates no error
  ACK_ERROR,   // indicates that there was an error
} handle_ack_status;

// an irdma_context (along with info about the received packet) is passed to each handle function
struct irdma_context {
  struct rxe_qp* qp;
};

// These IRDMA_REQ_OPNUMS arise out of the observation that all the existing entries in
// rxe_opcode have, in their 'mask' field, exactly one of the following 5 bits set:
// RXE_ACK_MASK, RXE_SEND_MASK, RXE_WRITE_MASK, RXE_READ_MASK, RXE_ATOMIC_MASK
// We separate this distinction out into IRDMA_REQ_OPNUMS, and we further separate
// RXE_ACK_MASK packets by having them be registered with a different function and
// by tracking them separately with the 'ack' field in rxe_opcode_info (among other things).
// We also observe that RXE_REQ_MASK is set iff RXE_ACK_MASK is not,
// and we generalize references to RXE_REQ_MASK to mean (not ack).
// Having these defined here is cheating for now, to allow other code to test
//   against IRDMA_* opnums.
// The reason I don't like this is that this prohibits new opnums from emulating
//   the same functionality as (wherever the test is happening).
// Ideally these should be defined only in irdma_opcode.c.
#ifndef IRDMA_REQ_OPNUMS
#define IRDMA_REQ_OPNUMS
typedef enum {
  IRDMA_REQ_SEND,
  IRDMA_REQ_WRITE,
  IRDMA_REQ_READ,
  IRDMA_REQ_ATOMIC,
} IRDMA_REQ_OPNUM;
#endif

enum rxe_wr_mask {
	WR_INLINE_MASK = BIT(0),
	WR_ATOMIC_MASK = BIT(1),
	WR_SEND_MASK = BIT(2),
	WR_READ_MASK = BIT(3),
	WR_WRITE_MASK = BIT(4),
    WR_IMMDT_MASK = BIT(5),
    WR_INV_MASK = BIT(6),
	WR_REG_MASK = BIT(7),
};

#define WR_MAX_QPT		(8)

struct rxe_opcode_set {
  unsigned start_opcode_num;
  unsigned middle_opcode_num;
  unsigned end_opcode_num;
  unsigned only_opcode_num;
};

struct rxe_wr_opcode_info {
	char			    *name;
	enum rxe_wr_mask	mask;
    bool                qpts[WR_MAX_QPT];  // which qpts this wr_opcode supports
    enum ib_wc_opcode   wc_opcode;
    bool                is_series;
    union {
      unsigned opcode_num;  // valid for is_series==FALSE
      struct rxe_opcode_set opcode_set; // valid for is_series==TRUE
        // '0' for opcode_num or for opcode_set.start_opcode_num indicates not yet registered
        // note that '0' is never valid here; we reserved the opcode value '0' (for this and for NAK)
        // TODO if someone tries to use not-yet-registered opcode num or set, give suitable error msg
    } opcodes[WR_MAX_QPT];
    unsigned            ack_opcode_num;
};

enum rxe_hdr_type {
	RXE_LRH,
	RXE_GRH,
	RXE_BTH,
	RXE_RETH,
	RXE_AETH,
	RXE_ATMETH,
	RXE_ATMACK,
	RXE_IETH,
	RXE_RDETH,
	RXE_DETH,
	RXE_IMMDT,
	RXE_PAYLOAD,
	NUM_HDR_TYPES
};

enum rxe_hdr_mask {
	RXE_LRH_MASK		= BIT(RXE_LRH),
	RXE_GRH_MASK		= BIT(RXE_GRH),
	RXE_BTH_MASK		= BIT(RXE_BTH),
	RXE_IMMDT_MASK		= BIT(RXE_IMMDT),
	RXE_RETH_MASK		= BIT(RXE_RETH),
	RXE_AETH_MASK		= BIT(RXE_AETH),
	RXE_ATMETH_MASK		= BIT(RXE_ATMETH),
	RXE_ATMACK_MASK		= BIT(RXE_ATMACK),
	RXE_IETH_MASK		= BIT(RXE_IETH),
	RXE_RDETH_MASK		= BIT(RXE_RDETH),
	RXE_DETH_MASK		= BIT(RXE_DETH),

    RXE_RWR_MASK		= BIT(NUM_HDR_TYPES + 0),
	RXE_COMP_MASK		= BIT(NUM_HDR_TYPES + 1),

	RXE_START_MASK		= BIT(NUM_HDR_TYPES + 2),
	RXE_MIDDLE_MASK		= BIT(NUM_HDR_TYPES + 3),
	RXE_END_MASK		= BIT(NUM_HDR_TYPES + 4),

	RXE_LOOPBACK_MASK	= BIT(NUM_HDR_TYPES + 5),

    IRDMA_SCHED_PRIORITY_MASK = BIT(NUM_HDR_TYPES + 6),
};

#define OPCODE_NONE		(-1)

struct rxe_opcode_info {
	char name[64];
	enum rxe_hdr_mask mask;
    bool is_ack;
    union {
      struct {
        IRDMA_REQ_OPNUM irdma_opnum;
        unsigned wr_opcode_num;
        handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*);
        handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*);
        unsigned char perms;
      } req;  // only valid if is_ack==FALSE
      struct {
        handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*);
      } ack;  // only valid if is_ack==TRUE
    };
    enum ib_qp_type qpt;
    unsigned series_id;
	int length;
	int offset[NUM_HDR_TYPES];
};

// store information about registered opcodes in these arrays
#define IRDMA_MAX_WR_OPCODES 32
extern struct rxe_wr_opcode_info rxe_wr_opcode_info[IRDMA_MAX_WR_OPCODES];
#define IRDMA_MAX_RXE_OPCODES 256
extern struct rxe_opcode_info rxe_opcode[IRDMA_MAX_RXE_OPCODES];

#define IRDMA_PERM_READ (IB_ACCESS_REMOTE_READ)
#define IRDMA_PERM_WRITE (IB_ACCESS_REMOTE_WRITE)
#define IRDMA_PERM_ATOMIC (IB_ACCESS_REMOTE_ATOMIC)
#define IRDMA_PERM_NONE (0)

typedef enum { OPCODE_OK = 0, OPCODE_INVALID, OPCODE_IN_USE } register_opcode_status;

// wr_opcode_num : the desired wr_opcode_num (not already in use)
// name : a name for the wr_opcode (max 63 characters, cannot be "")
// qpts : pointer to array of qp types this wr_opcode is compatible with
// num_qpts : length of the qpts array (number of compatible qp types)
// series : whether the wr_opcode is associated with a series of opcodes or not
//   For more information see comments on register_req_opcode_series()
// type : one of WR_SEND_MASK, WR_WRITE_MASK, WR_READ_MASK, WR_ATOMIC_MASK, or WR_REG_MASK
//   Better explanation TBD
// immdt : whether the operation should (in addition to whatever else it does) present an
//   immediate value to the receiver
// invalidate : whether the operation should (in addition to whatever else it does) 'invalidate'
//   a remote memory region.  'immdt' and 'invalidate' cannot both be TRUE.
// wr_inline : explanation TBD
// wc_opcode : the wc_opcode associated with this wr_opcode
//   that is, the opcode to place in the CQE for this wr
// ack_opcode_num : the opcode_num of the 'ack' expected in response to this wr_opcode
//   (previously registered either with register_single_ack_opcode or register_ack_opcode_series)
//   if we expect an opcode series rather than a single opcode, supply the *start* opcode
//     of the series as ack_opcode_num here.
//   Also note that this opcode is what is expected on *successful* ack; NAKs are handled
//     separately, and the ack_opcode_num does not affect the NAK process.
// returns:
//   OPCODE_OK on success
//   OPCODE_INVALID if:
//     - wr_opcode_num is outside allowed range
//     - ack_opcode_num has not been registered, or was not registered as required above
//     - the 'name' string is too long
//   OPCODE_IN_USE if the desired wr_opcode_num is already in use
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
    enum ib_wc_opcode wc_opcode,
    unsigned ack_opcode_num
);

// Register a 'request' opcode.  All opcodes except 'ack' opcodes are in this category.
// See register_single_ack_opcode for more on the distinction.
// opcode_num : the desired opcode number (not already in use, either as a 'req' opcode or
//   as an 'ack' opcode)
//   the special value 0 is reserved; you may not specify opcode_num==0
// name : a name for the opcode (max 63 characters, cannot be "")
// irdma_req_opnum : which of the IRDMA_REQ_OPNUMS this opcode belongs to.
//   Having this here is only a temporary measure, since it is (very) unextensible.
//   Hopefully, in the near future all functionality can be captured with the other
//   arguments, and nowhere in the code will test against specific irdma_req_opnums.
// handle_incoming : a function to be called to handle incoming packets of this type
//   (see also irdma_funcs.h)
// handle_duplicate : a function to be called to handle *duplicate* incoming packets of this type
//   (see also irdma_funcs.h)
// wr_opcode_num : the number of the wr_opcode for this opcode
//   (previously registered with register_wr_opcode, with series==FALSE)
//   Each wr_opcode can only have one req_opcode per qpt; you can't register multiple
//     (single_)req_opcodes with the same wr_opcode and qpt
// qpt : which qp type this opcode is to be used on (e.g. IB_QPT_RC, IB_QPT_UD, etc)
// requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
//   If immdt==TRUE, requiresReceive must be TRUE.
//   TODO: also if invalidate==TRUE?
// postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
//   If immdt==TRUE, postComplete must be TRUE.
//   TODO: also if invalidate==TRUE?
// perms : what permissions the *receiving* qp is required to have on *its* machine.
//   Should be one of IRDMA_PERM_READ, IRDMA_PERM_WRITE, IRDMA_PERM_ATOMIC, IRDMA_PERM_NONE
//   or a bitwise-OR of any of these, to require multiple permissions.
// sched_priority : to my current understanding, setting this to TRUE instructs the
//   internal scheduler to always handle an incoming packet of this type immediately,
//   pushing aside other tasks (e.g. posting sends, completes, etc).
//   In existing code, only IB_OPCODE_RC_RDMA_READ_REQUEST gets this treatment.
// returns :
//   OPCODE_OK on success
//   OPCODE_INVALID if:
//     - opcode_num is outside allowed range
//     - wr_opcode_num:
//        - has not been registered
//        - was registered with series==TRUE
//        - was not registered as supporting this qpt
//     - the 'name' string is too long
//     - the combination of arguments passed is invalid
//   OPCODE_IN_USE if:
//     - the desired opcode_num is already in use
//     - a different opcode_num was previously registered with the same wr_opcode_num and qpt
register_opcode_status register_single_req_opcode(
    unsigned opcode_num,
    char* name,
    IRDMA_REQ_OPNUM irdma_req_opnum,
    handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
    handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
    unsigned wr_opcode_num,
    enum ib_qp_type qpt,
    bool requiresReceive, bool postComplete, unsigned char perms, bool sched_priority
);

enum ynb { YES, NO, BOTH };

// Sometimes you want to transmit information that is (or may be) too large for a single packet.
// To do this, you need an "opcode series", which has four opcodes, indicating the
// 'start', 'middle', 'end', or 'only' of a series, respectively.
// Then, if you wanted to send a series of 5 packets, you would send them in the order
// 'start', 'middle', 'middle', 'middle', 'end'.
// A series of 3 packets would be 'start', 'middle', 'end'.
// A series of 2 packets would be 'start', 'end' omitting 'middle'.
// Finally, for the instance where all your data fits in a single packet, we have the 'only' packet.
// Arguments:
//   *_opcode_num: the four opcode numbers you wish to register
//   basename: basename for the opcodes; "_start" etc will be appended to form the individual names
//     This means the basename must be max 56 characters, if immdt==NO and invalidate==NO;
//     max 47 characters, if immdt==NO and invalidate==YES/BOTH;
//     or max 45 characters, if immdt==YES/BOTH
//   irdma_req_opnum: see comments on register_single_opcode.  Will apply to all four opcodes.
//   handle_incoming: see comments on register_single_opcode.  Will apply to all four opcodes.
//   handle_duplicate: see comments on register_single_opcode.  Will apply to all four opcodes.
//   wr_opcode_num: the number of the wr_opcode for these opcodes (will apply to all four opcodes)
//     (previously registered with register_wr_opcode, with series==TRUE)
//     Each wr_opcode can only have one req_opcode_series per qpt; you can't register multiple
//       req_opcode_series with the same wr_opcode and qpt
//   qpt: see comments on register_single_opcode.  Will apply to all four opcodes.
//   immdt: whether the series includes an immediate value to be presented to the receiver.
//     In any case, only the opcodes which end the series (i.e. 'end' and 'only') carry the immediate.
//     If YES, the 'end' and 'only' opcodes carry an immediate.  If NO, they don't.
//       In these two cases, wr_opcode_num must have been registered with immdt==TRUE/FALSE respectively.
//     If BOTH, then two different versions of the 'end' and 'only' opcodes will be registered;
//       versions without an immediate will be registered under end_opcode_num and only_opcode_num,
//       whereas versions with an immediate will be registered under
//       end_opcode_num_immdt and only_opcode_num_immdt.
//       You also must supply a wr_opcode_num_immdt which will be used for the immediate-carrying
//       version of the series (wr_opcode_num will be used for the non-immediate-carrying version).
//       wr_opcode_num_immdt must have been registered with immdt==TRUE, and wr_opcode_num with immdt==FALSE.
//     See also below, 'immdt--invalidate restriction'
//   end_opcode_num_immdt: see comments on 'immdt' above; only used if immdt==BOTH, else ignored
//   only_opcode_num_immdt: see comments on 'immdt' above; only used if immdt==BOTH, else ignored
//   wr_opcode_num_immdt: see comments on 'immdt' above; only used if immdt==BOTH, else ignored
//   invalidate : whether the packet should (in addition to whatever else it does) 'invalidate'
//     a remote memory region.
//     In any case, only the opcodes which end the series (i.e. 'end' and 'only') carry the invalidate.
//     If YES, the 'end' and 'only' opcodes carry an invalidate.  If NO, they don't.
//       In these two cases, wr_opcode_num must have been registered with invalidate==TRUE/FALSE respectively.
//     If BOTH, then two different versions of the 'end' and 'only' opcodes will be registered;
//       versions without an invalidate will be registered under end_opcode_num and only_opcode_num,
//       whereas versions with an invalidate will be registered under
//       end_opcode_num_inv and only_opcode_num_inv.
//       You also must supply a wr_opcode_num_inv which will be used for the invalidate-carrying
//       version of the series (wr_opcode_num will be used for the non-invalidate-carrying version).
//       wr_opcode_num_inv must have been registered with inv==TRUE, and wr_opcode_num with inv==FALSE.
//     See also below, 'immdt-invalidate restriction'
//   end_opcode_num_inv: see comments on 'invalidate' above; only used if invalidate==BOTH, else ignored
//   only_opcode_num_inv: see comments on 'invalidate' above; only used if invalidate==BOTH, else ignored
//   wr_opcode_num_inv: see comments on 'invalidate' above; only used if invalidate==BOTH, else ignored
//   requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
//     The 'receive' WQE will be required for opcodes which start the series (i.e. 'start' and 'only').
//     If requiresReceive==FALSE but the series carries an immediate, a 'receive' WQE will still be required,
//     but in this case for the opcodes which end the series (i.e. 'end' and 'only').
//     TODO: Unclear if we should handle requiresReceive==FALSE + invalidate similarly?
//       No examples of that case in the existing opcodes
//       Provisionally, I'm letting the requiresReceive==FALSE hold even for series carrying invalidates
//   postComplete : whether a 'cqe' should be posted to the completion queue upon operation completion
//     The 'cqe' will be posted with the opcodes which end the series (i.e. 'end' and 'only').
//     If immdt==YES, postComplete must be TRUE.  If immdt==BOTH, the value of this argument applies for
//     the non-immediate version of the series; the immediate version will implicitly have postComplete==TRUE
//     TODO: Unclear if we should handle invalidate==YES or invalidate==BOTH similarly?
//       No examples of postComplete==FALSE + invalidate==YES/BOTH in the existing opcodes
//       Provisionally, I'm treating invalidate==YES/BOTH like immdt==YES/BOTH for postComplete
//   perms : see comments on register_single_opcode.  Will apply to all four opcodes.
//   sched_priority : to my current understanding, setting this to TRUE instructs the
//     internal scheduler to always handle incoming packets from this series immediately,
//     pushing aside other tasks (e.g. posting sends, completes, etc).
//     In existing code, no series gets this treatment (only the single opcode IB_OPCODE_RC_RDMA_READ_REQUEST).
// immdt-invalidate restriction:
//   If either 'immdt' or 'invalidate' is YES, the other must be NO.
//   If both 'immdt' and 'invalidate' are BOTH, a total of three versions of the series will be registered:
//     one carrying neither immediate nor invalidate
//       (registered under end_opcode_num and only_opcode_num, with wr_opcode_num)
//     one carrying just an immediate
//       (registered under end_opcode_num_immdt and only_opcode_num_immdt, with wr_opcode_immdt)
//     one carrying just an invalidate
//       (registered under end_opcode_num_inv and only_opcode_num_inv, with wr_opcode_inv)
//   In particular, no series may carry both an immediate and an invalidate.
// returns:
//   OPCODE_OK on success
//   OPCODE_INVALID if:
//     - any of the opcode_nums (the ones that are not ignored per the rules above) are outside allowed range
//     - any of the (not-ignored) wr_opcode_nums:
//        - have not been registered
//        - were registered with series==FALSE
//        - were not registered as supporting this qpt
//     - the 'basename' string is too long
//     - the combination of arguments passed is invalid
//   OPCODE_IN_USE if:
//     - any of the (not-ignored) opcode_nums were already in use
//     - any of the (not-ignored) wr_opcode_nums were previously used for a different opcode_series
//         registration with the same qpt
//   In either of the error cases, the state when the function returns is guaranteed to be equivalent to
//     the state as if the erroneous function call never happened - none of the new items will be registered.
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
);

// Register an 'ack' opcode. 'ack' opcodes are issued in response to 'request' opcodes,
//   and only in RC qp's.  Among other differences, 'ack' packets cannot be requested through
//   a wr (only 'request' packets can be), so they do not need, and cannot have, an associated
//   wr_opcode.
// opcode_num : the desired opcode number (not already in use, either as a 'req' opcode or
//   as an 'ack' opcode)
//   the special value 0 is reserved; you may not specify opcode_num==0
// name : a name for this opcode (max 63 characters, cannot be "")
// handle_incoming : a function to be called to handle incoming 'ack' packets of this type
//   (see also irdma_funcs.h)
// atomicack : set to TRUE iff the packet is an ack/response to an atomic operation
// TODO: can we assume values of immdt, invalidate, requiresReceive, postComplete, and sched_priority
//   or do we need to include arguments here for one or more of them
// returns:
//   OPCODE_OK on success
//   OPCODE_INVALID if opcode_num is outside allowed range or if 'name' is too long
//   OPCODE_IN_USE if the desired opcode_num is already in use
register_opcode_status register_single_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
);

// Analogous to 'request' opcodes, we may also desire 'ack' opcode series. (For instance, if a response includes
// a potentially large amount of data.)  This function is similar to register_req_opcode_series, but for 'ack's.
// Arguments:
//   *_opcode_num : the four opcode numbers you wish to register
//   basename : basename for the opcodes; "_start" etc will be appended to form the individual names
//     This means the basename must be max 56 characters.
//   handle_incoming : see comments on register_single_ack_opcode.  Will apply to all four opcodes.
//   atomicack : see comments on register_single_ack_opcode.  Will apply to all four opcodes.
// returns:
//   OPCODE_OK on success
//   OPCODE_INVALID if any of the opcode_nums are outside allowed range or if 'basename' is too long
//   OPCODE_IN_USE if any of the opcode_nums were already in use
//   In either of the error cases, the state when the function returns is guaranteed to be equivalent to
//     the state as if the erroneous function call never happened - none of the new items will be registered.
register_opcode_status register_ack_opcode_series(
    unsigned start_opcode_num,
    unsigned middle_opcode_num,
    unsigned end_opcode_num,
    unsigned only_opcode_num,
    char* basename,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
);

#endif
