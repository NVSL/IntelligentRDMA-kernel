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
  INCOMING_ERROR_LENGTH,  // indicates that copy_data returned -ENOSPC,
                          // or that the payload was not the expected length
  INCOMING_ERROR_RKEY_VIOLATION,  // explanation TBD, but name seems straightforward
  INCOMING_ERROR_RNR,  // 'receiver not ready' - indicates that a required receive request was not posted
  INCOMING_ERROR_HANDLED,  // indicates that there was an error, but it has already been handled
} handle_incoming_status;

// handle_duplicate_status is the return type of the handle_duplicate function for a 'req' opcode.
typedef enum {
  HANDLED,    // duplicate packet has been handled, we're done
  REPROCESS,  // this code only for use in conjunction with ack series sending; better explanation TBD
} handle_duplicate_status;

// handle_ack_status is the return type of the handle_incoming function for an 'ack' opcode.
typedef enum {
  ACK_COMPLETE,  // indicates ack handled and operation complete
  ACK_NEXT,      // indicates ack handled but still waiting on more 'ack' packets (I think?)
  ACK_ERROR,     // indicates that there was an error
} handle_ack_status;

// handle_loc_status is the return type of the handle_wr function for a 'loc' wr.
typedef enum {
  LOC_OK = 0,  // indicates no error
  LOC_ERROR,   // indicates that there was an error
} handle_loc_status;

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

// rxe_opcode 0 is reserved for our special NAK operation, and for marking unregistered
#define IRDMA_OPCODE_NAK 0

enum rxe_wr_mask {
	WR_INLINE_MASK = BIT(0),
	WR_ATOMIC_MASK = BIT(1),
	WR_SEND_MASK = BIT(2),
	WR_READ_MASK = BIT(3),
	WR_WRITE_MASK = BIT(4),
    WR_IMMDT_MASK = BIT(5),
    WR_INV_MASK = BIT(6),
    WR_PAYLOAD_MASK = BIT(7),
    WR_SOLICITED_MASK = BIT(8),
    WR_COMP_MASK = BIT(9),
    WR_RETH_MASK = BIT(10),
    WR_ATMETH_MASK = BIT(11),
};

#define WR_MAX_QPT		(8)

enum rxe_wr_type {
  LOCAL = 0,
  STANDARD,
};

struct rxe_opcode_set {
  unsigned start_opcode_num;
  unsigned middle_opcode_num;
  unsigned end_opcode_num;
  unsigned only_opcode_num;
};

struct rxe_opcode_group {
  bool is_series;
  union {
    unsigned opcode_num;  // valid for is_series==FALSE
    struct rxe_opcode_set opcode_set;  // valid for is_series==TRUE
      // '0' for opcode_num or for opcode_set.start_opcode_num indicates not yet registered
      // note that '0' is never valid here; we reserved the opcode value '0' (for this and for NAK)
  };
};

unsigned series_id(struct rxe_opcode_group* opcode_group);
bool is_registered(struct rxe_opcode_group* opcode_group);

struct rxe_wr_opcode_info {
	char			    name[64];
	enum rxe_wr_mask	mask;
    enum rxe_wr_type    type;
    union {
      struct {
        handle_loc_status (*handle_wr)(struct irdma_context*, struct rxe_send_wqe*);
      } loc;  // valid for type==LOCAL
      struct {
        bool                qpts[WR_MAX_QPT];  // which qpts this wr_opcode supports
        enum ib_wc_opcode   sender_wc_opcode;
        enum ib_wc_opcode   receiver_wc_opcode;
        struct rxe_opcode_group opcode_groups[WR_MAX_QPT];
        struct rxe_opcode_group ack_opcode_group;
      } std;  // valid for type==STANDARD
    };
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
    IRDMA_RES_MASK      = BIT(NUM_HDR_TYPES + 7),
    IRDMA_COMPSWAP_MASK = BIT(NUM_HDR_TYPES + 8),
};

#define OPCODE_NONE		(-1)

struct rxe_opcode_info {
	char name[64];
	enum rxe_hdr_mask mask;
    bool is_ack;
    union {
      struct {
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
    struct rxe_opcode_group containingGroup;
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

typedef enum {
  OPCODE_OK = 0,
  OPCODE_NUM_OUTSIDE_RANGE,
  OPCODE_IN_USE,
  OPCODE_REG_ERROR,
  NAME_INVALID,
  ARGUMENTS_INVALID,
} register_opcode_status;

// Register a 'standard' work request opcode (wr_opcode).  'standard' wr's involve sending and/or
//   receiving packets.  Compare with 'local' wr_opcodes (register_loc_wr_opcode()).
// wr_opcode_num : the desired wr_opcode_num (not already in use, either for a 'local' or 'standard' wr)
// name : a name for the wr_opcode (max 63 characters, cannot be "")
// qpts : pointer to array of qp types this wr_opcode is compatible with
// num_qpts : length of the qpts array (number of compatible qp types)
// type : one of WR_SEND_MASK, WR_WRITE_MASK, WR_READ_MASK, or WR_ATOMIC_MASK
//   Better explanation TBD
// immdt : whether the operation should (in addition to whatever else it does) present an
//   immediate value to the receiver
// invalidate : whether the operation should (in addition to whatever else it does) 'invalidate'
//   a remote memory region.  'immdt' and 'invalidate' cannot both be TRUE.
// payload : whether the operation includes a 'payload' of data or not
//   TODO: in future could this be indicated by rxe_send_wqe.dma != NULL on the individual send
//   request, instead of by a flag on the wr?  It would be up to individual receiver functions
//   to handle the presence or absence of a payload 'correctly' (however the user defines that).
// remaddr : whether the operation should include a remote address (including rkey) specified
//   by the sender.  More formally, whether the operation's first (or only) packet should include
//   an 'RDMA extended transport header'.  This option is ignored if atomic==TRUE.
// atomic : whether the operation should include info necessary for atomic operations
//   (namely remoate address, rkey, 'swap', and 'compare_add') specified by the sender.
//   More formally, whether the operation's first (or only) packet should include an
//   'atomic extended transport header'.  If this option is TRUE, 'remaddr' is ignored.
// wr_inline : allow (but not require) 'IB_SEND_INLINE' flag with wr's having this wr_opcode
// alwaysEnableSolicited : the rules for whether to set the 'solicited' flag in the bth are
//   confusing to me.  First of all, the flag is never set unless the user dynamically specifies
//   'solicited' as part of the particular wr invocation (which is fine I guess).
//   Second of all, the flag is only set for the last packet associated with that particular wr
//   (which is also certainly fine).  But third of all, even if the first two conditions are met,
//   the flag is not set except for wr's with immdt==TRUE or with alwaysEnableSolicited==TRUE,
//   even overriding the user's expressed preference (dynamic 'solicited' flag).
//   In existing code, the 'RDMA Send' wr's have this set, but no others, so if you specify
//   solicited with your invocation of RDMA Read, or RDMA Write without immediate, the 'solicited'
//   flag still won't get set in the bth header of any of your packets.
//   One corollary of the above discussion is that if immdt==TRUE, alwaysEnableSolicited has no
//     effect (it effectively defaults to TRUE, kinda).
// sender_wc_opcode : the wc_opcode to place in the 'cqe' for the *sender's* cq upon successful
//   operation completion and ack
// postComplete : whether a 'cqe' should be posted to the *receiver's* cq upon successful operation
//   completion
//   If immdt==TRUE, postComplete must be TRUE.
//   Provisionally, also if invalidate==TRUE, postComplete must be TRUE.  I'm not sure if this
//     restriction is strictly necessary, but the existing code does obey it.
// receiver_wc_opcode : if postComplete==TRUE, the wc_opcode to place in the aforementioned 'cqe'
// ack_opcode_num : the opcode_num of the 'ack' expected in response to this wr_opcode
//   (previously registered either with register_single_ack_opcode or register_ack_opcode_series)
//   if we expect an opcode series rather than a single opcode, just put any opcode from the series
//     here and we'll figure it out.
//   Also note that this opcode is what is expected on *successful* ack; NAKs are handled
//     separately, and the ack_opcode_num does not affect the NAK process.
// returns:
//   OPCODE_OK on success
//   OPCODE_NUM_OUTSIDE_RANGE if wr_opcode_num is outside allowed range
//   OPCODE_IN_USE if the desired wr_opcode_num is already in use
//   OPCODE_REG_ERROR if:
//     - ack_opcode_num has not been registered
//     - ack_opcode_num was not registered as required above
//   NAME_INVALID if the 'name' string is too long, or is ""
//   ARGUMENTS_INVALID if the combination of arguments passed is invalid
register_opcode_status register_std_wr_opcode(
    unsigned wr_opcode_num,
    char* name,
    enum ib_qp_type* qpts,
    unsigned num_qpts,
    enum rxe_wr_mask type,
    bool immdt,
    bool invalidate,
    bool payload,
    bool remaddr,
    bool atomic,
    bool wr_inline,
    bool alwaysEnableSolicited,
    enum ib_wc_opcode sender_wc_opcode,
    bool postComplete, enum ib_wc_opcode receiver_wc_opcode,
    unsigned ack_opcode_num
);

// Register a 'local' work request opcode (wr_opcode).  'local' wr's do not need to send or
//   receive packets, that is, they operate entirely locally.  Compare with 'standard' wr's.
// wr_opcode_num : the desired wr_opcode_num (not already in use, either for a 'local' or 'standard' wr)
// name : a name for the wr_opcode (max 63 characters, cannot be "")
// handle_wr : a function to be called to handle wr's of this type (see also irdma_funcs.h)
// wr_inline : allow (but not require) 'IB_SEND_INLINE' flag with wr's having this wr_opcode
// returns:
//   OPCODE_OK on success
//   OPCODE_NUM_OUTSIDE_RANGE if wr_opcode_num is outside allowed range
//   OPCODE_IN_USE if the desired wr_opcode_num is already in use
//   NAME_INVALID if the 'name' string is too long, or is ""
register_opcode_status register_loc_wr_opcode(
    unsigned wr_opcode_num,
    char* name,
    handle_loc_status (*handle_wr)(struct irdma_context*, struct rxe_send_wqe*),
    bool wr_inline
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
//   (previously registered with register_*std*_wr_opcode)
//   Each wr_opcode can only have one req_opcode (or req_opcode_series) per qpt; you can't
//     register multiple req_opcodes (or req_opcode_series) with the same wr_opcode and qpt
// qpt : which qp type this opcode is to be used on (e.g. IB_QPT_RC, IB_QPT_UD, etc)
// requiresReceive : whether the operation requires that the receiver has posted a 'receive' WQE
//   If immdt==TRUE, requiresReceive must be TRUE.
//   TODO: also if invalidate==TRUE?
// perms : what permissions the *receiving* qp is required to have on *its* machine.
//   Should be one of IRDMA_PERM_READ, IRDMA_PERM_WRITE, IRDMA_PERM_ATOMIC, IRDMA_PERM_NONE
//   or a bitwise-OR of any of these, to require multiple permissions.
// sched_priority : to my current understanding, setting this to TRUE instructs the
//   internal scheduler to always handle an incoming packet of this type immediately,
//   pushing aside other tasks (e.g. posting sends, completes, etc).
//   In existing code, only IB_OPCODE_RC_RDMA_READ_REQUEST gets this treatment.
// comp_swap : set to TRUE for "compare-and-swap" atomic operations.  Better explanation TBD
// returns :
//   OPCODE_OK on success
//   OPCODE_NUM_OUTSIDE_RANGE if opcode_num is outside allowed range
//   OPCODE_IN_USE if:
//     - the desired opcode_num is already in use
//     - a different opcode_num was previously registered with the same wr_opcode_num and qpt
//   OPCODE_REG_ERROR if:
//     - wr_opcode_num has not been registered
//     - wr_opcode_num was registered with register_loc_wr_opcode
//     - wr_opcode_num was not registered as supporting this qpt
//   NAME_INVALID if the 'name' string is too long, or is ""
//   ARGUMENTS_INVALID if the combination of arguments passed is invalid
register_opcode_status register_single_req_opcode(
    unsigned opcode_num,
    char* name,
    IRDMA_REQ_OPNUM irdma_req_opnum,
    handle_incoming_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*),
    handle_duplicate_status (*handle_duplicate)(struct irdma_context*, struct rxe_pkt_info*),
    unsigned wr_opcode_num,
    enum ib_qp_type qpt,
    bool requiresReceive, unsigned char perms, bool sched_priority, bool comp_swap
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
//   *_opcode_num: the four opcode numbers you wish to register (must be distinct)
//   basename: basename for the opcodes; "_start" etc will be appended to form the individual names
//     This means the basename must be max 56 characters, if immdt==NO and invalidate==NO;
//     max 47 characters, if immdt==NO and invalidate==YES/BOTH;
//     or max 45 characters, if immdt==YES/BOTH
//   irdma_req_opnum: see comments on register_single_req_opcode.  Will apply to all four opcodes.
//   handle_incoming: see comments on register_single_req_opcode.  Will apply to all four opcodes.
//   handle_duplicate: see comments on register_single_req_opcode.  Will apply to all four opcodes.
//   wr_opcode_num: the number of the wr_opcode for these opcodes (will apply to all four opcodes)
//     (previously registered with register_*std*_wr_opcode)
//     Each wr_opcode can only have one req_opcode_series (or single req_opcode) per qpt; you can't
//       register multiple req_opcode_series (or single req_opcodes) with the same wr_opcode and qpt
//   qpt: see comments on register_single_req_opcode.  Will apply to all four opcodes.
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
//   perms : see comments on register_single_req_opcode.  Will apply to all four opcodes.
//   sched_priority : to my current understanding, setting this to TRUE instructs the
//     internal scheduler to always handle incoming packets from this series immediately,
//     pushing aside other tasks (e.g. posting sends, completes, etc).
//     In existing code, no series gets this treatment (only the single opcode IB_OPCODE_RC_RDMA_READ_REQUEST).
//   comp_swap : see comments on register_single_req_opcode.  Will apply to all four opcodes.
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
//   OPCODE_NUM_OUTSIDE_RANGE if any of the opcode_nums (the ones that are not ignored per the rules above)
//     are outside allowed range
//   OPCODE_IN_USE if:
//     - any of the (not-ignored) opcode_nums were already in use
//     - any of the (not-ignored) opcode_nums are not distinct
//     - any of the (not-ignored) wr_opcode_nums are not distinct
//     - any of the (not-ignored) wr_opcode_nums were previously used for a different req_opcode or
//         req_opcode_series registration with the same qpt
//   OPCODE_REG_ERROR if any of the (not-ignored) wr_opcode_nums:
//     - have not been registered
//     - were registered with register_loc_wr_opcode
//     - were not registered as supporting this qpt
//     - were registered with different values of 'atomic'
//     - were registered with different values of 'remaddr' (and have 'atomic'==FALSE)
//   NAME_INVALID if the 'basename' string is too long, or is ""
//   ARGUMENTS_INVALID if the combination of arguments passed is invalid
// In any of the error cases, the state when the function returns is guaranteed to be equivalent to
//   the state as if the erroneous function call never happened - none of the new items will be registered.
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
    bool requiresReceive, unsigned char perms, bool sched_priority, bool comp_swap
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
// returns:
//   OPCODE_OK on success
//   OPCODE_NUM_OUTSIDE_RANGE if opcode_num is outside allowed range
//   OPCODE_IN_USE if the desired opcode_num is already in use
//   NAME_INVALID if the 'name' string is too long, or is ""
register_opcode_status register_single_ack_opcode(
    unsigned opcode_num,
    char* name,
    handle_ack_status (*handle_incoming)(struct irdma_context*, struct rxe_pkt_info*, struct rxe_send_wqe*),
    bool atomicack
);

// Analogous to 'request' opcodes, we may also desire 'ack' opcode series. (For instance, if a response includes
// a potentially large amount of data.)  This function is similar to register_req_opcode_series, but for 'ack's.
// Arguments:
//   *_opcode_num : the four opcode numbers you wish to register (must be distinct)
//   basename : basename for the opcodes; "_start" etc will be appended to form the individual names
//     This means the basename must be max 56 characters.
//   handle_incoming : see comments on register_single_ack_opcode.  Will apply to all four opcodes.
//   atomicack : see comments on register_single_ack_opcode.  Will apply to all four opcodes.
// returns:
//   OPCODE_OK on success
//   OPCODE_NUM_OUTSIDE_RANGE if any of the opcode_nums are outside allowed range
//   OPCODE_IN_USE if any of the opcode_nums were already in use, or are not distinct
//   NAME_INVALID if the 'basename' string is too long, or is ""
// In any of the error cases, the state when the function returns is guaranteed to be equivalent to
//   the state as if the erroneous function call never happened - none of the new items will be registered.
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
