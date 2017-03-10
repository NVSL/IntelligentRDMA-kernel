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

#include <rdma/ib_pack.h>
#include "irdma.h"

/* useful information about work request opcodes and pkt opcodes in
 * table form
 */
struct rxe_wr_opcode_info rxe_wr_opcode_info[] = {
	[IB_WR_RDMA_WRITE]				= {
		.name	= "IB_WR_RDMA_WRITE",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[IB_WR_RDMA_WRITE_WITH_IMM]			= {
		.name	= "IB_WR_RDMA_WRITE_WITH_IMM",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[IB_WR_SEND]					= {
		.name	= "IB_WR_SEND",
		.mask	= {
			[IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_SEND_WITH_IMM]				= {
		.name	= "IB_WR_SEND_WITH_IMM",
		.mask	= {
			[IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_RDMA_READ]				= {
		.name	= "IB_WR_RDMA_READ",
		.mask	= {
			[IB_QPT_RC]	= WR_READ_MASK,
		},
	},
	[IB_WR_ATOMIC_CMP_AND_SWP]			= {
		.name	= "IB_WR_ATOMIC_CMP_AND_SWP",
		.mask	= {
			[IB_QPT_RC]	= WR_ATOMIC_MASK,
		},
	},
	[IB_WR_ATOMIC_FETCH_AND_ADD]			= {
		.name	= "IB_WR_ATOMIC_FETCH_AND_ADD",
		.mask	= {
			[IB_QPT_RC]	= WR_ATOMIC_MASK,
		},
	},
	[IB_WR_LSO]					= {
		.name	= "IB_WR_LSO",
		.mask	= {
			/* not supported */
		},
	},
	[IB_WR_SEND_WITH_INV]				= {
		.name	= "IB_WR_SEND_WITH_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[IB_WR_RDMA_READ_WITH_INV]			= {
		.name	= "IB_WR_RDMA_READ_WITH_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_READ_MASK,
		},
	},
	[IB_WR_LOCAL_INV]				= {
		.name	= "IB_WR_LOCAL_INV",
		.mask	= {
			[IB_QPT_RC]	= WR_REG_MASK,
		},
	},
	[IB_WR_REG_MR]					= {
		.name	= "IB_WR_REG_MR",
		.mask	= {
			[IB_QPT_RC]	= WR_REG_MASK,
		},
	},
};

struct rxe_opcode_info rxe_opcode[RXE_NUM_OPCODE];
