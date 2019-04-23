/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"

static void free_wq_pages(void *handle, struct hinic_wq *wq)
{
	dma_free_coherent(handle, wq->wq_buf_size, (void *)wq->queue_buf_vaddr,
			(dma_addr_t)wq->queue_buf_paddr);

	wq->queue_buf_paddr = 0;
	wq->queue_buf_vaddr = 0;
}

static int alloc_wq_pages(void *dev_hdl, struct hinic_wq *wq)
{
	dma_addr_t dma_addr = 0;

	wq->queue_buf_vaddr = (u64)(u64 *)
		dma_zalloc_coherent_aligned256k(dev_hdl, wq->wq_buf_size,
						&dma_addr, GFP_KERNEL);
	if (!wq->queue_buf_vaddr) {
		pr_err("Failed to allocate wq page\n");
		return -ENOMEM;
	}

	if (!ADDR_256K_ALIGNED(dma_addr)) {
		pr_err("Wqe pages is not 256k aligned!\n");
		dma_free_coherent(dev_hdl, wq->wq_buf_size,
				  (void *)wq->queue_buf_vaddr,
				  dma_addr);
		return -ENOMEM;
	}

	wq->queue_buf_paddr = dma_addr;

	return 0;
}

int hinic_wq_allocate(void *dev_hdl, struct hinic_wq *wq,
		      u32 wqebb_shift, u16 q_depth)
{
	int err;

	if (q_depth & (q_depth - 1)) {
		pr_err("WQ q_depth isn't power of 2\n");
		return -EINVAL;
	}

	wq->wqebb_size = 1 << wqebb_shift;
	wq->wqebb_shift = wqebb_shift;
	wq->wq_buf_size = ((u32)q_depth) << wqebb_shift;
	wq->q_depth = q_depth;

	if (wq->wq_buf_size > (PAGE_SIZE << HINIC_PAGE_SIZE_DPDK)) {
		pr_err("Invalid q_depth %u which one page_size can not hold\n",
			q_depth);
		return -EINVAL;
	}

	err = alloc_wq_pages(dev_hdl, wq);
	if (err) {
		pr_err("Failed to allocate wq pages\n");
		return err;
	}

	wq->cons_idx = 0;
	wq->prod_idx = 0;
	wq->delta = q_depth;
	wq->mask = q_depth - 1;

	return 0;
}

void hinic_wq_free(void *dev_hdl, struct hinic_wq *wq)
{
	free_wq_pages(dev_hdl, wq);
}

void hinic_put_wqe(struct hinic_wq *wq, int num_wqebbs)
{
	wq->cons_idx += num_wqebbs;
	wq->delta += num_wqebbs;
}

void *hinic_read_wqe(struct hinic_wq *wq, int num_wqebbs, u16 *cons_idx)
{
	u16 curr_cons_idx;

	if ((wq->delta + num_wqebbs) > wq->q_depth)
		return NULL;

	curr_cons_idx = (u16)(wq->cons_idx);

	curr_cons_idx = MASKED_WQE_IDX(wq, curr_cons_idx);

	*cons_idx = curr_cons_idx;

	return WQ_WQE_ADDR(wq, (u32)(*cons_idx));
}

int hinic_cmdq_alloc(struct hinic_wq *wq, void *dev_hdl,
		     int cmdq_blocks, u32 wq_buf_size, u32 wqebb_shift,
		     u16 q_depth)
{
	int i, j, err = -ENOMEM;

	/* validate q_depth is power of 2 & wqebb_size is not 0 */
	for (i = 0; i < cmdq_blocks; i++) {
		wq[i].wqebb_size = 1 << wqebb_shift;
		wq[i].wqebb_shift = wqebb_shift;
		wq[i].wq_buf_size = wq_buf_size;
		wq[i].q_depth = q_depth;

		err = alloc_wq_pages(dev_hdl, &wq[i]);
		if (err) {
			pr_err("Failed to alloc CMDQ blocks\n");
			goto cmdq_block_err;
		}

		wq[i].cons_idx = 0;
		wq[i].prod_idx = 0;
		wq[i].delta = q_depth;

		wq[i].mask = q_depth - 1;
	}

	return 0;

cmdq_block_err:
	for (j = 0; j < i; j++)
		free_wq_pages(dev_hdl, &wq[j]);

	return err;
}

void hinic_cmdq_free(void *dev_hdl, struct hinic_wq *wq, int cmdq_blocks)
{
	int i;

	for (i = 0; i < cmdq_blocks; i++)
		free_wq_pages(dev_hdl, &wq[i]);
}

void hinic_wq_wqe_pg_clear(struct hinic_wq *wq)
{
	wq->cons_idx = 0;
	wq->prod_idx = 0;

	memset((void *)wq->queue_buf_vaddr, 0, wq->wq_buf_size);
}

void *hinic_get_wqe(struct hinic_wq *wq, int num_wqebbs, u16 *prod_idx)
{
	u16 curr_prod_idx;

	wq->delta -= num_wqebbs;
	curr_prod_idx = wq->prod_idx;
	wq->prod_idx += num_wqebbs;
	*prod_idx = MASKED_WQE_IDX(wq, curr_prod_idx);

	return WQ_WQE_ADDR(wq, (u32)(*prod_idx));
}