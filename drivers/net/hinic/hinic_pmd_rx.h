/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_RX_H_
#define _HINIC_PMD_RX_H_

/* rxq wq operations */
#define HINIC_GET_RQ_WQE_MASK(rxq)	\
	((rxq)->wq->mask)

#define HINIC_GET_RQ_LOCAL_CI(rxq)	\
	(((rxq)->wq->cons_idx) & HINIC_GET_RQ_WQE_MASK(rxq))

#define HINIC_GET_RQ_LOCAL_PI(rxq)	\
	(((rxq)->wq->prod_idx) & HINIC_GET_RQ_WQE_MASK(rxq))

#define HINIC_UPDATE_RQ_LOCAL_CI(rxq, wqebb_cnt)	\
	(rxq)->wq->cons_idx += (wqebb_cnt);	\
	(rxq)->wq->delta += (wqebb_cnt)

#define HINIC_GET_RQ_FREE_WQEBBS(rxq)	\
	((rxq)->wq->delta - 1)

#define HINIC_UPDATE_RQ_HW_PI(rxq, pi)	\
	*((rxq)->pi_virt_addr) = cpu_to_be16((pi) & HINIC_GET_RQ_WQE_MASK(rxq));

#define HINIC_UPDATE_RQ_MASKED_HW_PI(rxq, pi)	\
	*(rxq)->pi_virt_addr = cpu_to_be16(pi);

/* rxq cqe done and status bit */
#define HINIC_GET_RX_DONE_BE(status)	\
	((status) & 0x80U)

#define HINIC_GET_RX_FLUSH_BE(status)	\
	((status) & 0x10U)

#define HINIC_DEFAULT_RX_FREE_THRESH	32

struct hinic_rxq_stats {
	u64 packets;
	u64 bytes;
	u64 rx_nombuf;
	u64 errors;
	u64 rx_discards;

#ifdef HINIC_XSTAT_MBUF_USE
	u64 alloc_mbuf;
	u64 free_mbuf;
	u64 left_mbuf;
#endif

#ifdef HINIC_XSTAT_RXBUF_INFO
	u64 rx_mbuf;
	u64 rx_avail;
	u64 rx_hole;
	u64 burst_pkts;
#endif

#ifdef HINIC_XSTAT_PROF_RX
	u64 app_tsc;
	u64 pmd_tsc;
#endif
};

/* Attention, Do not add any member in hinic_rx_info
 * as rxq bulk rearm mode will write mbuf in rx_info */
struct hinic_rx_info {
	struct rte_mbuf *mbuf;
};

struct hinic_rxq {
	struct hinic_wq *wq;
	volatile u16 *pi_virt_addr;

	u16 port_id;
	u16 q_id;
	u16 q_depth;
	u16 buf_len;

	u16 rx_free_thresh;
	u16 rxinfo_align_end;

	unsigned long status;
	struct hinic_rxq_stats rxq_stats;

	hinic_nic_dev *nic_dev;

	struct hinic_rx_info	*rx_info;
	volatile struct hinic_rq_cqe *rx_cqe;

	dma_addr_t cqe_start_paddr;
	void *cqe_start_vaddr;
	struct rte_mempool *mb_pool;

#ifdef HINIC_XSTAT_PROF_RX
	/* performance profiling */
	uint64_t prof_rx_end_tsc;
#endif
};

#ifdef HINIC_XSTAT_MBUF_USE
void hinic_rx_free_mbuf(struct hinic_rxq *rxq, struct rte_mbuf *m);
#else
void hinic_rx_free_mbuf(struct rte_mbuf *m);
#endif

int hinic_setup_rx_resources(struct hinic_rxq *rxq);

void hinic_free_all_rx_resources(struct rte_eth_dev *dev);

void hinic_free_all_rx_mbuf(struct rte_eth_dev *dev);

void hinic_free_rx_resources(struct hinic_rxq *rxq);

u16 hinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts);

void hinic_free_all_rx_skbs(struct hinic_rxq *rxq);

void hinic_rx_alloc_pkts(struct hinic_rxq *rxq);

void hinic_rxq_get_stats(struct hinic_rxq *rxq, struct hinic_rxq_stats *stats);

void hinic_rxq_stats_reset(struct hinic_rxq *rxq);

int hinic_config_mq_mode(struct rte_eth_dev *dev, bool on);

int hinic_rx_configure(struct rte_eth_dev *dev);

void hinic_rx_remove_configure(struct rte_eth_dev *dev);

#endif /* _HINIC_PMD_RX_H_ */