/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"

void hinic_prepare_rq_wqe(void *wqe, __rte_unused u16 pi, dma_addr_t buf_addr,
			  dma_addr_t cqe_dma)
{
	struct hinic_rq_wqe *rq_wqe = (struct hinic_rq_wqe *)wqe;
	struct hinic_rq_ctrl *ctrl = &rq_wqe->ctrl;
	struct hinic_rq_cqe_sect *cqe_sect = &rq_wqe->cqe_sect;
	struct hinic_rq_bufdesc *buf_desc = &rq_wqe->buf_desc;
	u32 rq_ceq_len = sizeof(struct hinic_rq_cqe);

	ctrl->ctrl_fmt =
		RQ_CTRL_SET(SIZE_8BYTES(sizeof(*ctrl)),  LEN) |
		RQ_CTRL_SET(SIZE_8BYTES(sizeof(*cqe_sect)), COMPLETE_LEN) |
		RQ_CTRL_SET(SIZE_8BYTES(sizeof(*buf_desc)), BUFDESC_SECT_LEN) |
		RQ_CTRL_SET(RQ_COMPLETE_SGE, COMPLETE_FORMAT);

	hinic_set_sge(&cqe_sect->sge, cqe_dma, rq_ceq_len);

	buf_desc->addr_high = upper_32_bits(buf_addr);
	buf_desc->addr_low = lower_32_bits(buf_addr);
}