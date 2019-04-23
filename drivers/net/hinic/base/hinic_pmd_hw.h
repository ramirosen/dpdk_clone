/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_HW_H_
#define _HINIC_PMD_HW_H_

#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__    0x4321
#endif

#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__    0x1234
#endif

#ifdef __BYTE_ORDER__
#undef __BYTE_ORDER__
#endif
/* X86 */
#define __BYTE_ORDER__    __LITTLE_ENDIAN__

#define HINIC_RECV_NEXT_AEQE	(HINIC_ERROR)
#define HINIC_RECV_DONE	        (HINIC_OK)

enum hinic_mod_type {
	HINIC_MOD_COMM = 0,	/* HW communication module */
	HINIC_MOD_L2NIC = 1,	/* L2NIC module */
	HINIC_MOD_CFGM = 7,	/* Configuration module */
	HINIC_MOD_HILINK = 14,
	HINIC_MOD_MAX	= 15
};

struct hinic_cmd_buf {
	void		*buf;
	dma_addr_t	dma_addr;
	struct rte_mbuf *mbuf;
	u16		size;
};

enum hinic_ack_type {
	HINIC_ACK_TYPE_CMDQ,
	HINIC_ACK_TYPE_SHARE_CQN,
	HINIC_ACK_TYPE_APP_CQN,

	HINIC_MOD_ACK_MAX = 15,

};

#endif /* _HINIC_PMD_HW_H_ */