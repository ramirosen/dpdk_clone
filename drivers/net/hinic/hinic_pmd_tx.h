/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_TX_H_
#define _HINIC_PMD_TX_H_

#define HINIC_DEFAULT_TX_FREE_THRESH	32
#define HINIC_MAX_TX_FREE_BULK		64

/* txq wq operations */
#define HINIC_GET_SQ_WQE_MASK(txq)	\
	((txq)->wq->mask)

#define HINIC_GET_SQ_HW_CI(txq)	\
	((be16_to_cpu(*(txq)->cons_idx_addr)) & HINIC_GET_SQ_WQE_MASK(txq))

#define HINIC_GET_SQ_LOCAL_CI(txq)	\
	(((txq)->wq->cons_idx) & HINIC_GET_SQ_WQE_MASK(txq))

#define HINIC_UPDATE_SQ_LOCAL_CI(txq, wqebb_cnt)	\
	(txq)->wq->cons_idx += wqebb_cnt;	\
	(txq)->wq->delta += wqebb_cnt

#define HINIC_GET_SQ_FREE_WQEBBS(txq)	\
		((txq)->wq->delta - 1)

#define HINIC_IS_SQ_EMPTY(txq)	\
		(((txq)->wq->delta) == ((txq)->q_depth))

#define HINIC_GET_WQ_TAIL(txq) ((txq)->wq->queue_buf_vaddr + \
				(txq)->wq->wq_buf_size)
#define HINIC_GET_WQ_HEAD(txq) ((txq)->wq->queue_buf_vaddr)

struct hinic_txq_stats {
	u64 packets;
	u64 bytes;
	u64 rl_drop;
	u64 tx_busy;
	u64 off_errs;
	u64 cpy_pkts;

#ifdef HINIC_XSTAT_PROF_TX
	u64 app_tsc;
	u64 pmd_tsc;
	u64 burst_pkts;
#endif
};

struct hinic_tx_info {
	struct rte_mbuf *mbuf;
	int wqebb_cnt;
	struct rte_mbuf *cpy_mbuf;
};

struct hinic_txq {
	/* cacheline0 */
	hinic_nic_dev *nic_dev;
	struct hinic_wq *wq;
	struct hinic_sq *sq;
	volatile u16 *cons_idx_addr;
	struct hinic_tx_info *tx_info;

	u16 tx_free_thresh;
	u16 port_id;
	u16 q_id;
	u16 q_depth;
	u32 cos;

	/* cacheline1 */
	struct hinic_txq_stats txq_stats;
	u64 sq_head_addr;
	u64 sq_bot_sge_addr;
#ifdef HINIC_XSTAT_PROF_TX
	uint64_t prof_tx_end_tsc; /* performance profiling */
#endif
};

int hinic_setup_tx_resources(struct hinic_txq *txq);

void hinic_free_all_tx_resources(struct rte_eth_dev *eth_dev);

void hinic_free_all_tx_mbuf(struct rte_eth_dev *eth_dev);

void hinic_free_tx_resources(struct hinic_txq *txq);

u16 hinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 nb_pkts);

void hinic_free_all_tx_skbs(struct hinic_txq *txq);

void hinic_txq_get_stats(struct hinic_txq *txq, struct hinic_txq_stats *stats);

void hinic_txq_stats_reset(struct hinic_txq *txq);

#endif /* _HINIC_PMD_TX_H_ */