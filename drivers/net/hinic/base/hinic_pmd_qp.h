/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_QP_H_
#define _HINIC_PMD_QP_H_

#define HINIC_MAX_QUEUE_DEPTH		4096
#define HINIC_MIN_QUEUE_DEPTH		128
#define HINIC_TXD_ALIGN                 1
#define HINIC_RXD_ALIGN                 1

struct hinic_sq_ctrl {
	u32	ctrl_fmt;
	u32	queue_info;
};

struct hinic_sq_task {
	u32		pkt_info0;
	u32		pkt_info1;
	u32		pkt_info2;
	u32		ufo_v6_identify;
	u32		pkt_info4;
	u32		rsvd5;
};

struct hinic_sq_bufdesc {
	struct hinic_sge sge;
	u32	rsvd;
};

struct hinic_sq_wqe {
	/* sq wqe control section */
	struct hinic_sq_ctrl		ctrl;

	/* sq task control section */
	struct hinic_sq_task		task;

	/* sq sge section start address, 1~127 sges */
	struct hinic_sq_bufdesc     buf_descs[0];
};

struct hinic_rq_ctrl {
	u32	ctrl_fmt;
};

struct hinic_rq_cqe {
	u32 status;
	u32 vlan_len;
	u32 offload_type;
	u32 rss_hash;

	u32 rsvd[4];
};

struct hinic_rq_cqe_sect {
	struct hinic_sge	sge;
	u32			rsvd;
};

struct hinic_rq_bufdesc {
	u32	addr_high;
	u32	addr_low;
};

struct hinic_rq_wqe {
	struct hinic_rq_ctrl		ctrl;
	u32				rsvd;
	struct hinic_rq_cqe_sect	cqe_sect;
	struct hinic_rq_bufdesc		buf_desc;
};

void hinic_prepare_rq_wqe(void *wqe, u16 pi, dma_addr_t buf_addr,
			  dma_addr_t cqe_dma);

#endif /* _HINIC_PMD_NICIO_H_ */