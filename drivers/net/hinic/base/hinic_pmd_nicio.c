/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"
#include "../hinic_pmd_rx.h"

#define WQ_PREFETCH_MAX			6
#define WQ_PREFETCH_MIN			1
#define WQ_PREFETCH_THRESHOLD		256

struct hinic_qp_ctxt_header {
	u16	num_queues;
	u16	queue_type;
	u32	addr_offset;
};

struct hinic_sq_ctxt {
	u32	ceq_attr;

	u32	ci_owner;

	u32	wq_pfn_hi;
	u32	wq_pfn_lo;

	u32	pref_cache;
	u32	pref_owner;
	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	rsvd8;
	u32	rsvd9;

	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct hinic_rq_ctxt {
	u32	ceq_attr;

	u32	pi_intr_attr;

	u32	wq_pfn_hi_ci;
	u32	wq_pfn_lo;

	u32	pref_cache;
	u32	pref_owner;

	u32	pref_wq_pfn_hi_ci;
	u32	pref_wq_pfn_lo;

	u32	pi_paddr_hi;
	u32	pi_paddr_lo;

	u32	wq_block_pfn_hi;
	u32	wq_block_pfn_lo;
};

struct hinic_sq_ctxt_block {
	struct hinic_qp_ctxt_header	cmdq_hdr;
	struct hinic_sq_ctxt		sq_ctxt[HINIC_Q_CTXT_MAX];
};

struct hinic_rq_ctxt_block {
	struct hinic_qp_ctxt_header	cmdq_hdr;
	struct hinic_rq_ctxt		rq_ctxt[HINIC_Q_CTXT_MAX];
};

struct hinic_clean_queue_ctxt {
	struct hinic_qp_ctxt_header	cmdq_hdr;
	u32				ctxt_size;
};

static void init_sq(struct hinic_sq *sq, struct hinic_wq *wq, u16 q_id,
		   volatile void *cons_idx_addr, void __iomem *db_addr)
{
	sq->wq = wq;
	sq->q_id = q_id;
	sq->owner = 1;

	sq->cons_idx_addr = (volatile u16 *)cons_idx_addr;
	sq->db_addr = db_addr;

	return;
}

static int init_rq(struct hinic_rq *rq, void *dev_hdl, struct hinic_wq *wq,
		   u16 q_id, __rte_unused u16 rq_msix_idx)
{
	rq->wq = wq;
	rq->q_id = q_id;

	rq->pi_virt_addr = (volatile u16 *)dma_zalloc_coherent(dev_hdl,
							       PAGE_SIZE,
							       &rq->pi_dma_addr,
							       GFP_KERNEL);
	if (!rq->pi_virt_addr) {
		dev_err(dev_hdl, "Failed to allocate pi virt addr\n");
		return -ENOMEM;
	}

	return 0;
}

static void clean_rq(struct hinic_rq *rq, void *dev_hdl)
{
	dma_free_coherent_volatile(dev_hdl, PAGE_SIZE,
				   (volatile void *)rq->pi_virt_addr,
				   rq->pi_dma_addr);
}

static void hinic_qp_prepare_cmdq_header(
				struct hinic_qp_ctxt_header *qp_ctxt_hdr,
				enum hinic_qp_ctxt_type ctxt_type,
				u16 num_queues, u16 max_queues, u16 q_id)
{
	qp_ctxt_hdr->queue_type = ctxt_type;
	qp_ctxt_hdr->num_queues = num_queues;

	if (ctxt_type == HINIC_QP_CTXT_TYPE_SQ)
		qp_ctxt_hdr->addr_offset =
				SQ_CTXT_OFFSET(max_queues, max_queues, q_id);
	else
		qp_ctxt_hdr->addr_offset =
				RQ_CTXT_OFFSET(max_queues, max_queues, q_id);

	qp_ctxt_hdr->addr_offset = SIZE_16BYTES(qp_ctxt_hdr->addr_offset);

	hinic_cpu_to_be32(qp_ctxt_hdr, sizeof(*qp_ctxt_hdr));
}

static void hinic_sq_prepare_ctxt(struct hinic_sq *sq, u16 global_qpn,
			   struct hinic_sq_ctxt *sq_ctxt)
{
	struct hinic_wq *wq = sq->wq;
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;

	ci_start = (u16)(wq->cons_idx);
	pi_start = (u16)(wq->prod_idx);

	/* read the first page from the HW table */
	wq_page_addr = wq->queue_buf_paddr;

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	wq_block_pfn = WQ_BLOCK_PFN(wq_page_addr);
	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	/* must config as ceq disabled */
	sq_ctxt->ceq_attr = SQ_CTXT_CEQ_ATTR_SET(global_qpn, GLOBAL_SQ_ID) |
				SQ_CTXT_CEQ_ATTR_SET(0, ARM) |
				SQ_CTXT_CEQ_ATTR_SET(0, CEQ_ID) |
				SQ_CTXT_CEQ_ATTR_SET(0, EN);

	sq_ctxt->ci_owner = SQ_CTXT_CI_SET(ci_start, IDX) |
				SQ_CTXT_CI_SET(1, OWNER);

	sq_ctxt->wq_pfn_hi =
			SQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
			SQ_CTXT_WQ_PAGE_SET(pi_start, PI);

	sq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	sq_ctxt->pref_cache =
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		SQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);

	sq_ctxt->pref_owner = 1;

	sq_ctxt->pref_wq_pfn_hi_ci =
		SQ_CTXT_PREF_SET(ci_start, CI) |
		SQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI);

	sq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	sq_ctxt->wq_block_pfn_hi =
		SQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	sq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	hinic_cpu_to_be32(sq_ctxt, sizeof(*sq_ctxt));
}

static void hinic_rq_prepare_ctxt(struct hinic_rq *rq,
			struct hinic_rq_ctxt *rq_ctxt)
{
	struct hinic_wq *wq = rq->wq;
	u64 wq_page_addr;
	u64 wq_page_pfn, wq_block_pfn;
	u32 wq_page_pfn_hi, wq_page_pfn_lo;
	u32 wq_block_pfn_hi, wq_block_pfn_lo;
	u16 pi_start, ci_start;

	ci_start = (u16)(wq->cons_idx);
	pi_start = (u16)(wq->prod_idx);

	/* read the first page from the HW table */
	wq_page_addr = wq->queue_buf_paddr;

	wq_page_pfn = WQ_PAGE_PFN(wq_page_addr);
	wq_page_pfn_hi = upper_32_bits(wq_page_pfn);
	wq_page_pfn_lo = lower_32_bits(wq_page_pfn);

	wq_block_pfn = WQ_BLOCK_PFN(wq_page_addr);
	wq_block_pfn_hi = upper_32_bits(wq_block_pfn);
	wq_block_pfn_lo = lower_32_bits(wq_block_pfn);

	/* must config as ceq enable but do not generate ceq */
	rq_ctxt->ceq_attr = RQ_CTXT_CEQ_ATTR_SET(1, EN) |
			    RQ_CTXT_CEQ_ATTR_SET(1, OWNER);

	rq_ctxt->pi_intr_attr = RQ_CTXT_PI_SET(pi_start, IDX) |
				RQ_CTXT_PI_SET(rq->msix_entry_idx, INTR) |
				RQ_CTXT_PI_SET(0, CEQ_ARM);

	rq_ctxt->wq_pfn_hi_ci = RQ_CTXT_WQ_PAGE_SET(wq_page_pfn_hi, HI_PFN) |
				RQ_CTXT_WQ_PAGE_SET(ci_start, CI);

	rq_ctxt->wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pref_cache =
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MIN, CACHE_MIN) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_MAX, CACHE_MAX) |
		RQ_CTXT_PREF_SET(WQ_PREFETCH_THRESHOLD, CACHE_THRESHOLD);

	rq_ctxt->pref_owner = 1;

	rq_ctxt->pref_wq_pfn_hi_ci =
		RQ_CTXT_PREF_SET(wq_page_pfn_hi, WQ_PFN_HI) |
		RQ_CTXT_PREF_SET(ci_start, CI);

	rq_ctxt->pref_wq_pfn_lo = wq_page_pfn_lo;

	rq_ctxt->pi_paddr_hi = upper_32_bits(rq->pi_dma_addr);
	rq_ctxt->pi_paddr_lo = lower_32_bits(rq->pi_dma_addr);

	rq_ctxt->wq_block_pfn_hi =
		RQ_CTXT_WQ_BLOCK_SET(wq_block_pfn_hi, PFN_HI);

	rq_ctxt->wq_block_pfn_lo = wq_block_pfn_lo;

	hinic_cpu_to_be32(rq_ctxt, sizeof(*rq_ctxt));
}

static int init_sq_ctxts(struct hinic_nic_io *nic_io)
{
	struct hinic_hwdev *hwdev = nic_io->hwdev;
	struct hinic_sq_ctxt_block *sq_ctxt_block;
	struct hinic_sq_ctxt *sq_ctxt;
	struct hinic_cmd_buf *cmd_buf;
	struct hinic_qp *qp;
	u64 out_param = EIO;
	u16 q_id, curr_id, global_qpn, max_ctxts, i;
	int err = 0;

	cmd_buf = hinic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		dev_err(hwdev->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	q_id = 0;
	/* sq and rq number may not equal */
	while (q_id < nic_io->num_sqs) {
		sq_ctxt_block = (struct hinic_sq_ctxt_block *)cmd_buf->buf;
		sq_ctxt = sq_ctxt_block->sq_ctxt;

		max_ctxts = (nic_io->num_sqs - q_id) > HINIC_Q_CTXT_MAX ?
				HINIC_Q_CTXT_MAX : (nic_io->num_sqs - q_id);

		hinic_qp_prepare_cmdq_header(&sq_ctxt_block->cmdq_hdr,
					     HINIC_QP_CTXT_TYPE_SQ, max_ctxts,
					     nic_io->max_qps, q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			qp = &nic_io->qps[curr_id];
			global_qpn = nic_io->global_qpn + curr_id;

			hinic_sq_prepare_ctxt(&qp->sq, global_qpn, &sq_ctxt[i]);
		}

		cmd_buf->size = SQ_CTXT_SIZE(max_ctxts);

		err = hinic_cmdq_direct_resp(hwdev, HINIC_ACK_TYPE_CMDQ,
					     HINIC_MOD_L2NIC,
					     HINIC_UCODE_CMD_MDY_QUEUE_CONTEXT,
					     cmd_buf, &out_param, 0);
		if ((err) || out_param != 0) {
			dev_err(hwdev->dev_hdl, "Failed to set SQ ctxts, err:%d, out_param:0x%lx\n",
				err, out_param);
			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	hinic_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

static int init_rq_ctxts(struct hinic_nic_io *nic_io)
{
	struct hinic_hwdev *hwdev = nic_io->hwdev;
	struct hinic_rq_ctxt_block *rq_ctxt_block;
	struct hinic_rq_ctxt *rq_ctxt;
	struct hinic_cmd_buf *cmd_buf;
	struct hinic_qp *qp;
	u64 out_param = 0;
	u16 q_id, curr_id, max_ctxts, i;
	int err = 0;

	cmd_buf = hinic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		dev_err(hwdev->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	q_id = 0;
	/* sq and rq number may not equal */
	while (q_id < nic_io->num_rqs) {
		rq_ctxt_block = (struct hinic_rq_ctxt_block *)cmd_buf->buf;
		rq_ctxt = rq_ctxt_block->rq_ctxt;

		max_ctxts = (nic_io->num_rqs - q_id) > HINIC_Q_CTXT_MAX ?
				HINIC_Q_CTXT_MAX : (nic_io->num_rqs - q_id);

		hinic_qp_prepare_cmdq_header(&rq_ctxt_block->cmdq_hdr,
					     HINIC_QP_CTXT_TYPE_RQ, max_ctxts,
					     nic_io->max_qps, q_id);

		for (i = 0; i < max_ctxts; i++) {
			curr_id = q_id + i;
			qp = &nic_io->qps[curr_id];

			hinic_rq_prepare_ctxt(&qp->rq, &rq_ctxt[i]);
		}

		cmd_buf->size = RQ_CTXT_SIZE(max_ctxts);

		err = hinic_cmdq_direct_resp(hwdev, HINIC_ACK_TYPE_CMDQ,
					     HINIC_MOD_L2NIC,
					     HINIC_UCODE_CMD_MDY_QUEUE_CONTEXT,
					     cmd_buf, &out_param, 0);

		if ((err) || out_param != 0) {
			dev_err(hwdev->dev_hdl, "Failed to set RQ ctxts\n");
			err = -EFAULT;
			break;
		}

		q_id += max_ctxts;
	}

	hinic_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

static int init_qp_ctxts(struct hinic_nic_io *nic_io)
{
	return (init_sq_ctxts(nic_io) || init_rq_ctxts(nic_io));
}

static int clean_queue_offload_ctxt(struct hinic_nic_io *nic_io,
				    enum hinic_qp_ctxt_type ctxt_type)
{
	struct hinic_hwdev *hwdev = nic_io->hwdev;
	struct hinic_clean_queue_ctxt *ctxt_block;
	struct hinic_cmd_buf *cmd_buf;
	u64 out_param = 0;
	int err;

	cmd_buf = hinic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		dev_err(hwdev->dev_hdl, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	ctxt_block = (struct hinic_clean_queue_ctxt *)cmd_buf->buf;
	ctxt_block->cmdq_hdr.num_queues = nic_io->max_qps;
	ctxt_block->cmdq_hdr.queue_type = ctxt_type;
	ctxt_block->cmdq_hdr.addr_offset = 0;

	/* TSO/LRO ctxt size: 0x0:0B; 0x1:160B; 0x2:200B; 0x3:240B */
	ctxt_block->ctxt_size = 0x3;

	hinic_cpu_to_be32(ctxt_block, sizeof(*ctxt_block));

	cmd_buf->size = sizeof(*ctxt_block);

	err = hinic_cmdq_direct_resp(hwdev, HINIC_ACK_TYPE_CMDQ,
				     HINIC_MOD_L2NIC,
				     HINIC_UCODE_CMD_CLEAN_QUEUE_CONTEXT,
				     cmd_buf, &out_param, 0);

	if ((err) || (out_param)) {
		dev_err(hwdev->dev_hdl, "Failed to clean queue offload ctxts\n");
		err = -EFAULT;
	}

	hinic_free_cmd_buf(hwdev, cmd_buf);

	return err;
}

static int clean_qp_offload_ctxt(struct hinic_nic_io *nic_io)
{
	/* clean LRO/TSO context space */
	return (clean_queue_offload_ctxt(nic_io, HINIC_QP_CTXT_TYPE_SQ) ||
		clean_queue_offload_ctxt(nic_io, HINIC_QP_CTXT_TYPE_RQ));
}

static void hinic_get_func_rx_buf_size(hinic_nic_dev *nic_dev)
{
	struct hinic_rxq *rxq;
	u16 q_id;
	u16 buf_size = 0;

	for (q_id = 0; q_id < nic_dev->num_rq; q_id++) {
		rxq = nic_dev->rxqs[q_id];

		if (rxq == NULL)
			continue;

		if (q_id == 0) {
			buf_size = rxq->buf_len;
		}

		buf_size = buf_size > rxq->buf_len ? rxq->buf_len : buf_size;
	}

	nic_dev->nic_io->rq_buf_size = buf_size;
}

/* init qps ctxt and set sq ci attr and arm all sq and set vat page_size */
int hinic_init_qp_ctxts(struct hinic_hwdev *hwdev)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_sq_attr sq_attr;
	u16 q_id;
	int err, rx_buf_sz;

	/* set vat page size to max queue depth page_size */
	err = hinic_set_pagesize(hwdev, HINIC_PAGE_SIZE_DPDK);
	if (err != HINIC_OK) {
		dev_err(hwdev->dev_hdl, "Set vat page size: %d failed, rc: %d\n",
			HINIC_PAGE_SIZE_DPDK, err);
		return err;
	}

	err = init_qp_ctxts(nic_io);
	if (err) {
		dev_err(hwdev->dev_hdl, "Init QP ctxts failed, rc: %d\n", err);
		return err;
	}

	/* clean LRO/TSO context space */
	err = clean_qp_offload_ctxt(nic_io);
	if (err) {
		dev_err(hwdev->dev_hdl, "Clean qp offload ctxts failed, rc: %d\n",
			err);
		return err;
	}

	/* get func rx buf size */
	hinic_get_func_rx_buf_size((hinic_nic_dev *)(hwdev->dev_hdl));
	rx_buf_sz = nic_io->rq_buf_size;

	/* update rx buf size to function table */
	err = hinic_set_rx_vhd_mode(hwdev, 0, rx_buf_sz);
	if (err) {
		dev_err(hwdev->dev_hdl, "Set rx vhd mode failed, rc: %d\n",
			err);
		return err;
	}

	err = hinic_set_root_ctxt(hwdev, nic_io->rq_depth,
				  nic_io->sq_depth, rx_buf_sz);
	if (err) {
		dev_err(hwdev->dev_hdl, "Set root context failed, rc: %d\n",
			err);
		return err;
	}

	for (q_id = 0; q_id < nic_io->num_sqs; q_id++) {
		sq_attr.ci_dma_base =
			HINIC_CI_PADDR(nic_io->ci_dma_base, q_id) >> 2;
		/* performance: sq ci update threshold as 8 */
		sq_attr.pending_limit = 1;
		sq_attr.coalescing_time = 1;
		sq_attr.intr_en = 0;
		sq_attr.l2nic_sqn = q_id;
		sq_attr.dma_attr_off = 0;
		err = hinic_set_ci_table(hwdev, q_id, &sq_attr);
		if (err) {
			dev_err(hwdev->dev_hdl, "Set ci table failed, rc: %d\n",
				err);
			goto set_cons_idx_table_err;
		}
	}

	return 0;

set_cons_idx_table_err:
	(void)hinic_clean_root_ctxt(hwdev);
	return err;
}

void hinic_free_qp_ctxts(struct hinic_hwdev *hwdev)
{
	int err;

	err = hinic_clean_root_ctxt(hwdev);
	if (err)
		dev_err(hwdev->dev_hdl, "Failed to clean root ctxt\n");
}

static int hinic_init_nic_hwdev(struct hinic_hwdev *hwdev)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	u16 global_qpn, rx_buf_sz;
	int err;

	err = hinic_get_base_qpn(hwdev, &global_qpn);
	if (err) {
		dev_err(hwdev->dev_hdl, "Failed to get base qpn\n");
		goto err_init_nic_hwdev;
	}

	nic_io->global_qpn = global_qpn;
	rx_buf_sz = HINIC_IS_VF(hwdev) ? RX_BUF_LEN_1_5K : RX_BUF_LEN_16K;
	err = hinic_init_function_table(hwdev, rx_buf_sz);
	if (err) {
		dev_err(hwdev->dev_hdl, "Failed to init function table\n");
		goto err_init_nic_hwdev;
	}

	err = hinic_set_fast_recycle_mode(hwdev, RECYCLE_MODE_DPDK);
	if (err) {
		dev_err(hwdev->dev_hdl, "Failed to set fast recycle mode\n");
		goto err_init_nic_hwdev;
	}

	return 0;

err_init_nic_hwdev:
	return err;
}

static void hinic_free_nic_hwdev(struct hinic_hwdev *hwdev)
{
	hwdev->nic_io = NULL;
}

int hinic_rx_tx_flush(struct hinic_hwdev *hwdev)
{
	return hinic_func_rx_tx_flush(hwdev);
}

int hinic_get_sq_free_wqebbs(struct hinic_hwdev *hwdev, u16 q_id)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_wq *wq = &nic_io->sq_wq[q_id];

	return (wq->delta) - 1;
}

int hinic_get_rq_free_wqebbs(struct hinic_hwdev *hwdev, u16 q_id)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_wq *wq = &nic_io->rq_wq[q_id];

	return (wq->delta) - 1;
}

u16 hinic_get_sq_local_ci(struct hinic_hwdev *hwdev, u16 q_id)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_wq *wq = &nic_io->sq_wq[q_id];

	return (wq->cons_idx) & wq->mask;
}

void hinic_return_sq_wqe(struct hinic_hwdev *hwdev, u16 q_id,
			 int num_wqebbs, u16 owner)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_sq *sq = &nic_io->qps[q_id].sq;

	if (owner != sq->owner)
		sq->owner = owner;

	sq->wq->delta += num_wqebbs;
	sq->wq->prod_idx -= num_wqebbs;
}

void hinic_update_sq_local_ci(struct hinic_hwdev *hwdev,
			      u16 q_id, int wqebb_cnt)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_sq *sq = &nic_io->qps[q_id].sq;

	hinic_put_wqe(sq->wq, wqebb_cnt);
}

void *hinic_get_rq_wqe(struct hinic_hwdev *hwdev, u16 q_id, u16 *pi)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_rq *rq = &nic_io->qps[q_id].rq;

	return hinic_get_wqe(rq->wq, 1, pi);
}

void hinic_return_rq_wqe(struct hinic_hwdev *hwdev, u16 q_id, int num_wqebbs)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_rq *rq = &nic_io->qps[q_id].rq;

	rq->wq->delta += num_wqebbs;
	rq->wq->prod_idx -= num_wqebbs;
}

u16 hinic_get_rq_local_ci(struct hinic_hwdev *hwdev, u16 q_id)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_wq *wq = &nic_io->rq_wq[q_id];

	return (wq->cons_idx) & wq->mask;
}

void hinic_update_rq_local_ci(struct hinic_hwdev *hwdev, u16 q_id, int wqe_cnt)
{
	struct hinic_nic_io *nic_io = hwdev->nic_io;
	struct hinic_rq *rq = &nic_io->qps[q_id].rq;

	hinic_put_wqe(rq->wq, wqe_cnt);
}

int hinic_create_rq(hinic_nic_dev *nic_dev, u16 q_id, u16 rq_depth)
{
	int err;
	struct hinic_nic_io *nic_io;
	struct hinic_qp *qp;
	struct hinic_rq *rq;
	struct hinic_hwdev *hwdev;

	hwdev = nic_dev->hwdev;
	nic_io = hwdev->nic_io;
	qp = &nic_io->qps[q_id];
	rq = &qp->rq;

	/* in case of hardware still generate interrupt, do not use msix 0 */
	rq->msix_entry_idx = 1;

	rq->rq_depth = rq_depth;
	nic_io->rq_depth = rq_depth;

	err = hinic_wq_allocate(hwdev->dev_hdl, &nic_io->rq_wq[q_id],
				HINIC_RQ_WQEBB_SHIFT, nic_io->rq_depth);
	if (err) {
		dev_err(nic_io->hwdev->dev_hdl, "Failed to allocate WQ for RQ\n");
		goto rq_alloc_err;
	}

	err = init_rq(rq, hwdev->dev_hdl, &nic_io->rq_wq[q_id],
		      q_id, 0);
	if (err) {
		dev_err(hwdev->dev_hdl, "Failed to init RQ\n");
		goto rq_init_err;
	}

	return HINIC_OK;

rq_init_err:
	hinic_wq_free(hwdev->dev_hdl, &nic_io->rq_wq[q_id]);

rq_alloc_err:
	return err;
}

void hinic_destroy_rq(hinic_nic_dev *nic_dev, u16 q_id)
{
	struct hinic_nic_io *nic_io;
	struct hinic_qp *qp;
	struct hinic_hwdev *hwdev;

	hwdev = nic_dev->hwdev;
	nic_io = hwdev->nic_io;
	qp = &nic_io->qps[q_id];

	if (qp->rq.wq == NULL)
		return;

	clean_rq(&qp->rq, nic_io->hwdev->dev_hdl);
	hinic_wq_free(nic_io->hwdev->dev_hdl, qp->rq.wq);
	qp->rq.wq = NULL;
}

int hinic_create_sq(hinic_nic_dev *nic_dev, u16 q_id, u16 sq_depth)
{
	int err;
	struct hinic_nic_io *nic_io;
	struct hinic_qp *qp;
	struct hinic_sq *sq;
	void __iomem *db_addr;
	struct hinic_hwdev *hwdev;
	volatile u32 *ci_addr;

	hwdev = nic_dev->hwdev;
	nic_io = hwdev->nic_io;
	qp = &nic_io->qps[q_id];
	sq = &qp->sq;

	sq->sq_depth = sq_depth;
	nic_io->sq_depth = sq_depth;

	/* alloc wq */
	err = hinic_wq_allocate(nic_io->hwdev->dev_hdl, &nic_io->sq_wq[q_id],
				HINIC_SQ_WQEBB_SHIFT, nic_io->sq_depth);
	if (err) {
		dev_err(nic_io->hwdev->dev_hdl, "Failed to allocate WQ for SQ\n");
		return err;
	}

	/* alloc sq doorbell space */
	err = hinic_alloc_db_addr(nic_io->hwdev, &db_addr, NULL);
	if (err) {
		dev_err(nic_io->hwdev->dev_hdl, "Failed to init db addr\n");
		goto alloc_db_err;
	}

	/* clear hardware ci */
	ci_addr = (volatile u32 *)HINIC_CI_VADDR(nic_io->ci_vaddr_base, q_id);
	*ci_addr = 0;

	/* init sq qheader */
	init_sq(sq, &nic_io->sq_wq[q_id], q_id,
	      (volatile void *)ci_addr, db_addr);

	return HINIC_OK;

alloc_db_err:
	hinic_wq_free(nic_io->hwdev->dev_hdl, &nic_io->sq_wq[q_id]);

	return err;
}

void hinic_destroy_sq(hinic_nic_dev *nic_dev, u16 q_id)
{
	struct hinic_nic_io *nic_io;
	struct hinic_qp *qp;
	struct hinic_hwdev *hwdev;

	hwdev = nic_dev->hwdev;
	nic_io = hwdev->nic_io;
	qp = &nic_io->qps[q_id];

	if (qp->sq.wq == NULL)
		return;

	hinic_free_db_addr(nic_io->hwdev, qp->sq.db_addr, NULL);
	hinic_wq_free(nic_io->hwdev->dev_hdl, qp->sq.wq);
	qp->sq.wq = NULL;
}

static int hinic_alloc_nicio(hinic_nic_dev *nic_dev)
{
	int err;
	u16 max_qps, num_qp;
	struct hinic_nic_io *nic_io;
	struct hinic_hwdev *hwdev = nic_dev->hwdev;

	if (!hwdev) {
		pr_err("hwdev is NULL\n");
		return -EFAULT;
	}

	nic_io = hwdev->nic_io;

	max_qps = hinic_func_max_qnum(hwdev);
	if ((max_qps & (max_qps - 1))) {
		dev_err(hwdev->dev_hdl, "wrong number of max_qps: %d\n",
			max_qps);
		return -EINVAL;
	}

	nic_io->max_qps = max_qps;
	nic_io->num_qps = max_qps;
	num_qp = max_qps;

	nic_io->qps = (struct hinic_qp *)
		kzalloc_aligned(num_qp * sizeof(*nic_io->qps), GFP_KERNEL);
	if (!nic_io->qps) {
		pr_err("Failed to allocate qps\n");
		err = -ENOMEM;
		goto alloc_qps_err;
	}

	nic_io->ci_vaddr_base = dma_zalloc_coherent(hwdev->dev_hdl,
						    CI_TABLE_SIZE(num_qp,
						    		  PAGE_SIZE),
						    &nic_io->ci_dma_base,
						    GFP_KERNEL);
	if (!nic_io->ci_vaddr_base) {
		dev_err(hwdev->dev_hdl, "Failed to allocate ci area\n");
		err = -ENOMEM;
		goto ci_base_err;
	}

	nic_io->sq_wq = (struct hinic_wq *)
		kzalloc_aligned(num_qp * sizeof(*nic_io->sq_wq), GFP_KERNEL);
	if (!nic_io->sq_wq) {
		pr_err("Failed to allocate sq wq array\n");
		err = -ENOMEM;
		goto sq_wq_err;
	}

	nic_io->rq_wq = (struct hinic_wq *)
		kzalloc_aligned(num_qp * sizeof(*nic_io->rq_wq), GFP_KERNEL);
	if (!nic_io->rq_wq) {
		pr_err("Failed to allocate rq wq array\n");
		err = -ENOMEM;
		goto rq_wq_err;
	}

	return HINIC_OK;

rq_wq_err:
	kfree(nic_io->sq_wq);

sq_wq_err:
	dma_free_coherent(hwdev->dev_hdl, CI_TABLE_SIZE(num_qp, PAGE_SIZE),
			  nic_io->ci_vaddr_base, nic_io->ci_dma_base);

ci_base_err:
	kfree(nic_io->qps);

alloc_qps_err:
	return err;
}

static void hinic_free_nicio(hinic_nic_dev *nic_dev)
{
	struct hinic_hwdev *hwdev = nic_dev->hwdev;
	struct hinic_nic_io *nic_io = hwdev->nic_io;

	/* nic_io->rq_wq */
	kfree(nic_io->rq_wq);

	/* nic_io->sq_wq */
	kfree(nic_io->sq_wq);

	/* nic_io->ci_vaddr_base */
	dma_free_coherent(hwdev->dev_hdl,
			  CI_TABLE_SIZE(nic_io->max_qps, PAGE_SIZE),
			  nic_io->ci_vaddr_base, nic_io->ci_dma_base);

	/* nic_io->qps */
	kfree(nic_io->qps);
}

/* alloc nic hwdev and init function table */
int hinic_init_nicio(hinic_nic_dev *nic_dev)
{
	int rc;

	nic_dev->nic_io =
		(struct hinic_nic_io *)rte_zmalloc("hinic_nicio",
						   sizeof(*nic_dev->nic_io),
						   RTE_CACHE_LINE_SIZE);
	HINIC_ERR_RET(nic_dev, NULL == nic_dev->nic_io,
		      -ENOMEM, "Alloc hinic_nicio failed");

	nic_dev->nic_io->hwdev = nic_dev->hwdev;
	nic_dev->hwdev->nic_io = nic_dev->nic_io;

	/* alloc root working queue set */
	rc = hinic_alloc_nicio(nic_dev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto allc_nicio_fail,
			 "Alloc nicio failed, nic_dev: %s",
			 nic_dev->proc_dev_name);

	rc = hinic_init_nic_hwdev(nic_dev->nic_io->hwdev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto init_nic_hwdev_fail,
			 "Init nic hwdev failed, nic_dev: %s",
			 nic_dev->proc_dev_name);
	return 0;

init_nic_hwdev_fail:
	hinic_free_nicio(nic_dev);

allc_nicio_fail:
	rte_free(nic_dev->nic_io);
	return rc;
}

void hinic_deinit_nicio(hinic_nic_dev *nic_dev)
{
	hinic_free_nicio(nic_dev);

	hinic_free_nic_hwdev(nic_dev->nic_io->hwdev);

	rte_free(nic_dev->nic_io);
	nic_dev->nic_io = NULL;
}