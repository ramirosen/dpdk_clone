/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_NICIO_H_
#define _HINIC_PMD_NICIO_H_

#define RX_BUF_LEN_16K	16384
#define RX_BUF_LEN_4K	4096
#define RX_BUF_LEN_1_5K	1536

#define SQ_CTRL_SET(val, member)	(((val) & SQ_CTRL_##member##_MASK) \
					<< SQ_CTRL_##member##_SHIFT)

struct hinic_sq_db {
	u32	db_info;
};

struct hinic_sge {
	u32		hi_addr;
	u32		lo_addr;
	u32		len;
};

struct hinic_event {
	void (*tx_ack)(void *handle, u16 q_id);
	/* status: 0 - link down; 1 - link up */
	void (*link_change)(void *handle, int status);
};

/* init qps ctxt and set sq ci attr and arm all sq */
int hinic_init_qp_ctxts(struct hinic_hwdev *hwdev);
void hinic_free_qp_ctxts(struct hinic_hwdev *hwdev);
int hinic_rx_tx_flush(struct hinic_hwdev *hwdev);

int hinic_get_sq_free_wqebbs(struct hinic_hwdev *hwdev, u16 q_id);
u16 hinic_get_sq_local_ci(struct hinic_hwdev *hwdev, u16 q_id);
void hinic_update_sq_local_ci(struct hinic_hwdev *hwdev, u16 q_id,
			      int wqebb_cnt);
void hinic_return_sq_wqe(struct hinic_hwdev *hwdev, u16 q_id,
			 int num_wqebbs, u16 owner);

int hinic_get_rq_free_wqebbs(struct hinic_hwdev *hwdev, u16 q_id);
void *hinic_get_rq_wqe(struct hinic_hwdev *hwdev, u16 q_id, u16 *pi);
void hinic_return_rq_wqe(struct hinic_hwdev *hwdev, u16 q_id, int num_wqebbs);
u16 hinic_get_rq_local_ci(struct hinic_hwdev *hwdev, u16 q_id);
void hinic_update_rq_local_ci(struct hinic_hwdev *hwdev, u16 q_id, int wqe_cnt);

void hinic_cpu_to_be32(void *data, int len);
void hinic_be32_to_cpu(void *data, int len);
void hinic_set_sge(struct hinic_sge *sge, dma_addr_t addr, u32 len);

#endif /* _HINIC_PMD_NICIO_H_ */