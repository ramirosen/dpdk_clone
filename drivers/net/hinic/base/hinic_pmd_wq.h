/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_WQ_H_
#define _HINIC_PMD_WQ_H_

#define	WQ_WQE_ADDR(wq, idx) ((void *)((u64)((wq)->queue_buf_vaddr) + \
			      ((idx) << (wq)->wqebb_shift)))

/* Working Queue */
struct hinic_wq {
	/* The addresses are 64 bit in the HW */
	u64     queue_buf_vaddr;

	u16		q_depth;
	u16		mask;
	u32		delta;

	u32		cons_idx;
	u32		prod_idx;

	u64     queue_buf_paddr;

	u32		wqebb_size;
	u32		wqebb_shift;

	u32		wq_buf_size;

	u32		rsvd[5];
};

void hinic_wq_wqe_pg_clear(struct hinic_wq *wq);

int hinic_cmdq_alloc(struct hinic_wq *wq, void *dev_hdl,
		     int cmdq_blocks, u32 wq_buf_size, u32 wqebb_shift,
		     u16 q_depth);

void hinic_cmdq_free(void *dev_hdl, struct hinic_wq *wq, int cmdq_blocks);

int hinic_wq_allocate(void *dev_hdl, struct hinic_wq *wq,
		      u32 wqebb_shift, u16 q_depth);

void hinic_wq_free(void *dev_hdl, struct hinic_wq *wq);

void *hinic_get_wqe(struct hinic_wq *wq, int num_wqebbs, u16 *prod_idx);

void hinic_put_wqe(struct hinic_wq *wq, int num_wqebbs);

void *hinic_read_wqe(struct hinic_wq *wq, int num_wqebbs, u16 *cons_idx);

#endif /* _HINIC_PMD_WQ_H_ */