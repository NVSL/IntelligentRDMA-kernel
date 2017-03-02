#include <rdma/ib_pack.h>  // BIT(), maybe among other things
#include "rxe_opcode.h"
#include "rxe_hdr.h"

typedef enum { OK, INVALID, IN_USE } register_opcode_status;

// opcode_num : the desired opcode number (not already in use)
// name : a name for the opcode
// mask : bitwise-OR of any of the flags defined in the rxe_hdr_mask
//  (e.g. RXE_PAYLOAD_MASK, RXE_START_MASK, etc)
// returns OK on success
//   INVALID if opcode_num is outside allowed range
//   IN_USE if the desired opcode_num is already in use
register_opcode_status register_opcode(
    unsigned opcode_num,
    char* name,
    enum rxe_hdr_mask mask
);

void computeOffset(struct rxe_opcode_info* info);
