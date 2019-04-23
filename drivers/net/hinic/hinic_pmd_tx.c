/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_udp.h>
#include <rte_ip.h>

#include "hinic_pmd_ethdev.h"
#include "hinic_pmd_tx.h"

/* packet header and tx offload info */
#define VXLANLEN                (8)
#define MAX_PLD_OFFSET          (221)
#define MAX_SINGLE_SGE_SIZE      (65536)
#define TSO_ENABLE              (1)

#define HINIC_NONTSO_PKT_MAX_SGE (17)	/* non-tso max sge 17 */
#define HINIC_NONTSO_SEG_NUM_INVAILD(num)  ((num) > HINIC_NONTSO_PKT_MAX_SGE)

#define HINIC_TSO_PKT_MAX_SGE (127)	/* tso max sge 127 */
#define HINIC_TSO_SEG_NUM_INVAILD(num)  ((num) > HINIC_TSO_PKT_MAX_SGE)

#define HINIC_TX_CKSUM_OFFLOAD_MASK (	\
		PKT_TX_IP_CKSUM |	\
		PKT_TX_TCP_CKSUM |	\
		PKT_TX_UDP_CKSUM |      \
		PKT_TX_OUTER_IP_CKSUM |	\
		PKT_TX_TCP_SEG)

/* sizeof(struct hinic_sq_bufdesc) == 16, shift 4 */
#define HINIC_BUF_DESC_SIZE(nr_descs)	\
		(SIZE_8BYTES(((u32)nr_descs) << 4))

/* tx offload info */
struct hinic_tx_offload_info {
	u8 outer_l2_len;
	u8 outer_l3_type;
	u8 outer_l3_len;

	u8 inner_l2_len;
	u8 inner_l3_type;
	u8 inner_l3_len;

	u8 tunnel_length;
	u8 tunnel_type;
	u8 inner_l4_type;
	u8 inner_l4_len;

	u8 payload_offset;
	u8 inner_l4_tcp_udp;
};

/* tx sge info */
struct hinic_wqe_info {
	u16 pi;
	u16 owner;
	u16 around;
	u16 seq_wqebbs;
	u16 sge_cnt;
	u16 cpy_mbuf_cnt;
};

/* performance: byteorder swap m128i */
static inline void hinic_sq_wqe_cpu_to_be32(void *data, int nr_wqebb)
{
	int i;
	__m128i *wqe_line = (__m128i *)data;
	__m128i shuf_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10,
					 11, 4, 5, 6, 7, 0, 1, 2, 3);

	for (i = 0; i < nr_wqebb; i++) {
		/* convert 64B wqebb using 4 SSE instructions */
		wqe_line[0] = _mm_shuffle_epi8(wqe_line[0], shuf_mask);
		wqe_line[1] = _mm_shuffle_epi8(wqe_line[1], shuf_mask);
		wqe_line[2] = _mm_shuffle_epi8(wqe_line[2], shuf_mask);
		wqe_line[3] = _mm_shuffle_epi8(wqe_line[3], shuf_mask);
		wqe_line += 4;
	}
}

static inline void hinic_sge_cpu_to_be32(void *data, int nr_sge)
{
	int i;
	__m128i *sge_line = (__m128i *)data;
	__m128i shuf_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10,
					 11, 4, 5, 6, 7, 0, 1, 2, 3);

	for (i = 0; i < nr_sge; i++) {
		/* convert 16B sge using 1 SSE instructions */
		*sge_line = _mm_shuffle_epi8(*sge_line, shuf_mask);
		sge_line++;
	}
}

void hinic_txq_get_stats(struct hinic_txq *txq, struct hinic_txq_stats *stats)
{
	if (!txq || !stats) {
		pr_err("Txq or stats is NULL\n");
		return;
	}

	memcpy(stats, &txq->txq_stats, sizeof(txq->txq_stats));
}

void hinic_txq_stats_reset(struct hinic_txq *txq)
{
	struct hinic_txq_stats *txq_stats;

	if (txq == NULL)
		return;

	txq_stats = &txq->txq_stats;
	memset(txq_stats, 0, sizeof(*txq_stats));
}

static inline struct rte_mbuf *hinic_copy_tx_mbuf(hinic_nic_dev *nic_dev,
						  struct rte_mbuf *mbuf,
						  u16 sge_cnt)
{
	struct rte_mbuf *dst_mbuf;
	u32 offset = 0;
	u16 i;

	if (unlikely(!nic_dev->cpy_mpool))
		return NULL;

	dst_mbuf = rte_pktmbuf_alloc(nic_dev->cpy_mpool);
	if (unlikely(!dst_mbuf))
		return NULL;

	dst_mbuf->data_off = 0;
	for (i = 0; i < sge_cnt; i++) {
		rte_memcpy((char *)dst_mbuf->buf_addr + offset,
			   (char *)mbuf->buf_addr + mbuf->data_off,
			   mbuf->data_len);
		dst_mbuf->data_len += mbuf->data_len;
		offset += mbuf->data_len;
		mbuf = mbuf->next;
	}

	return dst_mbuf;
}

static inline bool hinic_mbuf_dma_map_sge(struct hinic_txq *txq,
					  struct rte_mbuf *mbuf,
					  struct hinic_sq_bufdesc *sges,
					  struct hinic_wqe_info *sqe_info)
{
	dma_addr_t dma_addr;
	u16 i, around_sges;
	u16 nb_segs = sqe_info->sge_cnt - sqe_info->cpy_mbuf_cnt;
	u16 real_nb_segs = mbuf->nb_segs;
	struct hinic_sq_bufdesc *sge_idx = sges;

	if(unlikely(sqe_info->around)) {
		/* parts of wqe is in sq bottom while parts
		 * of wqe is in sq head
		 */
		i = 0;
		for (sge_idx = sges; (u64)sge_idx <= txq->sq_bot_sge_addr;
		     sge_idx++) {
			dma_addr = rte_mbuf_data_iova(mbuf);
			hinic_set_sge((struct hinic_sge *)sge_idx, dma_addr,
				      mbuf->data_len);
			mbuf = mbuf->next;
			i++;
		}

		around_sges = nb_segs - i;
		sge_idx = (struct hinic_sq_bufdesc *)((void *)txq->sq_head_addr);
		for (; i < nb_segs; i++) {
			dma_addr = rte_mbuf_data_iova(mbuf);
			hinic_set_sge((struct hinic_sge *)sge_idx, dma_addr,
				      mbuf->data_len);
			mbuf = mbuf->next;
			sge_idx++;
		}

		/* covert sges at head to big endian */
		hinic_sge_cpu_to_be32((void *)txq->sq_head_addr, around_sges);
	} else {
		/* wqe is in continuous space */
		for (i = 0; i < nb_segs; i++) {
			dma_addr = rte_mbuf_data_iova(mbuf);
			hinic_set_sge((struct hinic_sge *)sge_idx, dma_addr,
				      mbuf->data_len);
			mbuf = mbuf->next;
			sge_idx++;
		}
	}

	/* for now: support non-tso over 17 sge, copy the last 2 mbuf */
	if (unlikely(sqe_info->cpy_mbuf_cnt != 0)) {
		/* copy invalid mbuf segs to a valid buffer, lost performance */
		txq->txq_stats.cpy_pkts += 1;
		mbuf = hinic_copy_tx_mbuf(txq->nic_dev, mbuf,
					  real_nb_segs - nb_segs);
		if (unlikely(!mbuf))
			return false;

		txq->tx_info[sqe_info->pi].cpy_mbuf = mbuf;

		/* deal with the last mbuf */
		dma_addr = rte_mbuf_data_iova(mbuf);
		hinic_set_sge((struct hinic_sge *)sge_idx, dma_addr,
			      mbuf->data_len);
		if (unlikely(sqe_info->around))
			hinic_sge_cpu_to_be32((void *)sge_idx, 1);
	}

	return true;
}

static inline void hinic_fill_sq_wqe_header(struct hinic_sq_ctrl *ctrl,
					    u32 queue_info, int nr_descs,
					    u8 owner)
{
	u32 ctrl_size, task_size, bufdesc_size;

	ctrl_size = SIZE_8BYTES(sizeof(struct hinic_sq_ctrl));
	task_size = SIZE_8BYTES(sizeof(struct hinic_sq_task));
	bufdesc_size = HINIC_BUF_DESC_SIZE(nr_descs);

	ctrl->ctrl_fmt = SQ_CTRL_SET(bufdesc_size, BUFDESC_SECT_LEN) |
			SQ_CTRL_SET(task_size, TASKSECT_LEN)	|
			SQ_CTRL_SET(SQ_NORMAL_WQE, DATA_FORMAT)	|
			SQ_CTRL_SET(ctrl_size, LEN)		|
			SQ_CTRL_SET(owner, OWNER);

	ctrl->queue_info = queue_info;
	ctrl->queue_info |= SQ_CTRL_QUEUE_INFO_SET(1U, UC);

	if (!SQ_CTRL_QUEUE_INFO_GET(ctrl->queue_info, MSS)) {
		ctrl->queue_info |=
			SQ_CTRL_QUEUE_INFO_SET(TX_MSS_DEFAULT, MSS);
	} else if (SQ_CTRL_QUEUE_INFO_GET(ctrl->queue_info, MSS) < TX_MSS_MIN) {
		/* mss should not be less than 80 */
		ctrl->queue_info =
				SQ_CTRL_QUEUE_INFO_CLEAR(ctrl->queue_info, MSS);
		ctrl->queue_info |= SQ_CTRL_QUEUE_INFO_SET(TX_MSS_MIN, MSS);
	}
}

static inline bool hinic_is_tso_sge_valid(struct rte_mbuf *mbuf,
					  struct hinic_tx_offload_info
					  *poff_info,
					  struct hinic_wqe_info *sqe_info)
{
	u32 total_len, limit_len, checked_len, left_len;
	u32 i, first_mss_sges, left_sges;
	struct rte_mbuf *mbuf_head, *mbuf_pre;

	left_sges = mbuf->nb_segs;
	mbuf_head = mbuf;

	/* tso sge number validation */
	if (unlikely(left_sges >= HINIC_NONTSO_PKT_MAX_SGE)) {
		checked_len = 0;
		limit_len = mbuf->tso_segsz + poff_info->payload_offset;
		first_mss_sges = HINIC_NONTSO_PKT_MAX_SGE;

		/* each continues 17 mbufs segmust do one check */
		while(left_sges >= HINIC_NONTSO_PKT_MAX_SGE) {
			/* total len of first 16 mbufs must equal
			 * or more than limit_len
			 */
			total_len = 0;
			for (i = 0; i < first_mss_sges; i++) {
				total_len += mbuf->data_len;
				mbuf_pre = mbuf;
				mbuf = mbuf->next;
				if (total_len >= limit_len) {
					limit_len = mbuf_head->tso_segsz;
					break;
				}
			}

			checked_len += total_len;

			/* try to copy if not valid */
			if (unlikely(first_mss_sges == i)) {
				left_sges -= first_mss_sges;
				checked_len -= mbuf_pre->data_len;

				left_len = mbuf_head->pkt_len - checked_len;
				if (left_len > HINIC_COPY_MBUF_SIZE)
					return false;

				sqe_info->sge_cnt = mbuf_head->nb_segs -
							left_sges;
				sqe_info->cpy_mbuf_cnt = 1;

				return true;
			} else {
				first_mss_sges = (HINIC_NONTSO_PKT_MAX_SGE - 1);
			}

			/* continue next 16 mbufs */
			left_sges -= (i + 1);
		} /* end of while */
	}

	sqe_info->sge_cnt = mbuf_head->nb_segs;
	return true;
}

static inline void
hinic_set_l4_csum_info(struct hinic_sq_task *task,
		u32 *queue_info, struct hinic_tx_offload_info *poff_info)
{
	u32 tcp_udp_cs, sctp;
	u16 l2hdr_len;

	sctp = 0;
	if (unlikely(SCTP_OFFLOAD_ENABLE == poff_info->inner_l4_type))
		sctp = 1;

	tcp_udp_cs = poff_info->inner_l4_tcp_udp;

	if (TUNNEL_UDP_NO_CSUM == poff_info->tunnel_type) {
		l2hdr_len =  poff_info->outer_l2_len;

		task->pkt_info2 |=
		SQ_TASK_INFO2_SET(poff_info->outer_l3_type, OUTER_L3TYPE) |
		SQ_TASK_INFO2_SET(poff_info->outer_l3_len, OUTER_L3LEN);
		task->pkt_info2 |=
		SQ_TASK_INFO2_SET(poff_info->tunnel_type, TUNNEL_L4TYPE) |
		SQ_TASK_INFO2_SET(poff_info->tunnel_length, TUNNEL_L4LEN);
	} else {
		l2hdr_len = poff_info->inner_l2_len;
	}

	task->pkt_info0 |= SQ_TASK_INFO0_SET(l2hdr_len, L2HDR_LEN);
	task->pkt_info1 |=
		SQ_TASK_INFO1_SET(poff_info->inner_l3_len, INNER_L3LEN);
	task->pkt_info0 |=
		SQ_TASK_INFO0_SET(poff_info->inner_l3_type, INNER_L3TYPE);
	task->pkt_info1 |=
		SQ_TASK_INFO1_SET(poff_info->inner_l4_len, INNER_L4LEN);
	task->pkt_info0 |=
		SQ_TASK_INFO0_SET(poff_info->inner_l4_type, L4OFFLOAD);
	*queue_info |=
		SQ_CTRL_QUEUE_INFO_SET(poff_info->payload_offset, PLDOFF) |
		SQ_CTRL_QUEUE_INFO_SET(tcp_udp_cs, TCPUDP_CS) |
		SQ_CTRL_QUEUE_INFO_SET(sctp, SCTP);
}

static inline void
hinic_set_tso_info(struct hinic_sq_task *task,
		u32 *queue_info, struct rte_mbuf *mbuf,
		struct hinic_tx_offload_info *poff_info)
{
	hinic_set_l4_csum_info(task, queue_info, poff_info);

	/* wqe for tso */
	task->pkt_info0 |=
		SQ_TASK_INFO0_SET(poff_info->inner_l3_type, INNER_L3TYPE);
	task->pkt_info0 |= SQ_TASK_INFO0_SET(TSO_ENABLE, TSO_UFO);
	*queue_info |= SQ_CTRL_QUEUE_INFO_SET(TSO_ENABLE, TSO);
	/* qsf was initialized in prepare_sq_wqe */
	*queue_info = SQ_CTRL_QUEUE_INFO_CLEAR(*queue_info, MSS);
	*queue_info |= SQ_CTRL_QUEUE_INFO_SET(mbuf->tso_segsz, MSS);
}

static inline void
hinic_set_vlan_tx_offload(struct hinic_sq_task *task,
			u32 *queue_info, u16 vlan_tag, u16 vlan_pri)
{
	task->pkt_info0 |= SQ_TASK_INFO0_SET(vlan_tag, VLAN_TAG) |
				SQ_TASK_INFO0_SET(1U, VLAN_OFFLOAD);

	*queue_info |= SQ_CTRL_QUEUE_INFO_SET(vlan_pri, PRI);
}

static inline void
hinic_fill_tx_offload_info(struct rte_mbuf *mbuf,
		struct hinic_sq_task *task, u32 *queue_info,
		struct hinic_tx_offload_info *tx_off_info)
{
	u16 vlan_tag;
	uint64_t ol_flags = mbuf->ol_flags;

	/* clear DW0~2 of task section for offload */
	task->pkt_info0 = 0;
	task->pkt_info1 = 0;
	task->pkt_info2 = 0;

	/* Base VLAN */
	if (unlikely(ol_flags & PKT_TX_VLAN_PKT)) {
		vlan_tag = mbuf->vlan_tci;
		hinic_set_vlan_tx_offload(task, queue_info, vlan_tag,
					  vlan_tag >> VLAN_PRIO_SHIFT);
	}

	/* non checksum or tso */
	if (unlikely(!(ol_flags & HINIC_TX_CKSUM_OFFLOAD_MASK)))
		return;

	if ((ol_flags & PKT_TX_TCP_SEG))
		/* set tso info for task and qsf */
		hinic_set_tso_info(task, queue_info, mbuf, tx_off_info);
	else /* just support l4 checksum offload */
		hinic_set_l4_csum_info(task, queue_info, tx_off_info);
}

static inline void hinic_xmit_mbuf_cleanup(struct hinic_txq *txq)
{
	struct hinic_tx_info *tx_info;
	struct rte_mbuf *mbuf, *m, *mbuf_free[HINIC_MAX_TX_FREE_BULK];
	int i, nb_free = 0;
	u16 hw_ci, sw_ci, sq_mask;
	int wqebb_cnt = 0;

	hw_ci = HINIC_GET_SQ_HW_CI(txq);
	sw_ci = HINIC_GET_SQ_LOCAL_CI(txq);
	sq_mask = HINIC_GET_SQ_WQE_MASK(txq);

	for (i = 0; i < txq->tx_free_thresh; ++i) {
		tx_info = &txq->tx_info[sw_ci];
		if ((hw_ci == sw_ci) ||
			(((hw_ci - sw_ci) & sq_mask) < tx_info->wqebb_cnt))
			break;

		sw_ci = (sw_ci + tx_info->wqebb_cnt) & sq_mask;

		if (unlikely(tx_info->cpy_mbuf != NULL)) {
			rte_pktmbuf_free(tx_info->cpy_mbuf);
			tx_info->cpy_mbuf = NULL;
		}

		wqebb_cnt += tx_info->wqebb_cnt;
		mbuf = tx_info->mbuf;

		if (likely(mbuf->nb_segs == 1)) {
			m = rte_pktmbuf_prefree_seg(mbuf);
			tx_info->mbuf = NULL;

			if (unlikely(m == NULL))
				continue;

			mbuf_free[nb_free++] = m;
			if (unlikely((m->pool != mbuf_free[0]->pool) ||
				(nb_free >= HINIC_MAX_TX_FREE_BULK))) {
				rte_mempool_put_bulk(mbuf_free[0]->pool,
					(void **)mbuf_free, (nb_free - 1));
				nb_free = 0;
				mbuf_free[nb_free++] = m;
			}
		} else {
			rte_pktmbuf_free(mbuf);
			tx_info->mbuf = NULL;
		}
	}

	if (nb_free > 0)
		rte_mempool_put_bulk(mbuf_free[0]->pool, (void **)mbuf_free, nb_free);

	HINIC_UPDATE_SQ_LOCAL_CI(txq, wqebb_cnt);
}

static inline struct hinic_sq_wqe *
hinic_get_sq_wqe(struct hinic_txq *txq, int wqebb_cnt,
		struct hinic_wqe_info *wqe_info)
{
	u32 cur_pi, end_pi;
	u16 remain_wqebbs;
	struct hinic_sq *sq = txq->sq;
	struct hinic_wq *wq = txq->wq;

	/* record current pi */
	cur_pi = MASKED_WQE_IDX(wq, wq->prod_idx);
	end_pi = cur_pi + wqebb_cnt;

	/* update next pi and delta */
	wq->prod_idx += wqebb_cnt;
	wq->delta -= wqebb_cnt;

	/* return current pi and owner */
	wqe_info->pi = cur_pi;
	wqe_info->owner = sq->owner;
	wqe_info->around = 0;
	wqe_info->seq_wqebbs = wqebb_cnt;

	if (unlikely(end_pi >= txq->q_depth)) {
		/* update owner of next prod_idx */
		sq->owner = !sq->owner;

		/* turn around to head */
		if (unlikely(end_pi > txq->q_depth)) {
			wqe_info->around = 1;
			remain_wqebbs = txq->q_depth - cur_pi;
			wqe_info->seq_wqebbs = remain_wqebbs;
		}
	}

	return (struct hinic_sq_wqe *)WQ_WQE_ADDR(wq, cur_pi);
}

static inline int
hinic_validate_tx_offload(const struct rte_mbuf *m)
{
	uint64_t ol_flags = m->ol_flags;
	uint64_t inner_l3_offset = m->l2_len;

	/* just support vxlan offload */
	if ((ol_flags & PKT_TX_TUNNEL_MASK) &&
	    !(ol_flags & PKT_TX_TUNNEL_VXLAN))
		return -ENOTSUP;

	if (ol_flags & PKT_TX_OUTER_IP_CKSUM)
		inner_l3_offset += m->outer_l2_len + m->outer_l3_len;

	/* Headers are fragmented */
	if (rte_pktmbuf_data_len(m) < inner_l3_offset + m->l3_len + m->l4_len)
		return -ENOTSUP;

	/* IP checksum can be counted only for IPv4 packet */
	if ((ol_flags & PKT_TX_IP_CKSUM) && (ol_flags & PKT_TX_IPV6))
		return -EINVAL;

	/* IP type not set when required */
	if (ol_flags & (PKT_TX_L4_MASK | PKT_TX_TCP_SEG)) {
		if (!(ol_flags & (PKT_TX_IPV4 | PKT_TX_IPV6)))
			return -EINVAL;
	}

	/* Check requirements for TSO packet */
	if (ol_flags & PKT_TX_TCP_SEG) {
		if ((m->tso_segsz == 0) ||
			((ol_flags & PKT_TX_IPV4) &&
			!(ol_flags & PKT_TX_IP_CKSUM)))
			return -EINVAL;
	}

	/* PKT_TX_OUTER_IP_CKSUM set for non outer IPv4 packet. */
	if ((ol_flags & PKT_TX_OUTER_IP_CKSUM) &&
		!(ol_flags & PKT_TX_OUTER_IPV4))
		return -EINVAL;

	return 0;
}

static inline uint16_t
hinic_ipv4_phdr_cksum(const struct ipv4_hdr *ipv4_hdr, uint64_t ol_flags)
{
	struct ipv4_psd_header {
		uint32_t src_addr; /* IP address of source host. */
		uint32_t dst_addr; /* IP address of destination host. */
		uint8_t  zero;     /* zero. */
		uint8_t  proto;    /* L4 protocol type. */
		uint16_t len;      /* L4 length. */
	} psd_hdr;
	uint8_t ihl;

	psd_hdr.src_addr = ipv4_hdr->src_addr;
	psd_hdr.dst_addr = ipv4_hdr->dst_addr;
	psd_hdr.zero = 0;
	psd_hdr.proto = ipv4_hdr->next_proto_id;
	if (ol_flags & PKT_TX_TCP_SEG) {
		psd_hdr.len = 0;
	} else {
		/* ipv4_hdr->version_ihl is uint8_t big endian, ihl locates
		 * lower 4 bits and unit is 4 bytes
		 */
		ihl = (ipv4_hdr->version_ihl & 0xF) << 2;
		psd_hdr.len =
			rte_cpu_to_be_16(
				rte_be_to_cpu_16(ipv4_hdr->total_length) - ihl);
	}
	return rte_raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

static inline uint16_t
hinic_ipv6_phdr_cksum(const struct ipv6_hdr *ipv6_hdr, uint64_t ol_flags)
{
	uint32_t sum;
	struct {
		uint32_t len;   /* L4 length. */
		uint32_t proto; /* L4 protocol - top 3 bytes must be zero */
	} psd_hdr;

	psd_hdr.proto = (ipv6_hdr->proto << 24);
	if (ol_flags & PKT_TX_TCP_SEG) {
		psd_hdr.len = 0;
	} else {
		psd_hdr.len = ipv6_hdr->payload_len;
	}

	sum = __rte_raw_cksum(ipv6_hdr->src_addr,
		sizeof(ipv6_hdr->src_addr) + sizeof(ipv6_hdr->dst_addr), 0);
	sum = __rte_raw_cksum(&psd_hdr, sizeof(psd_hdr), sum);
	return __rte_raw_cksum_reduce(sum);
}

static inline int
hinic_tx_offload_pkt_prepare(struct rte_mbuf *m,
				struct hinic_tx_offload_info *off_info)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ipv6_hdr *ipv6_hdr;
	struct tcp_hdr *tcp_hdr;
	struct udp_hdr *udp_hdr;
	struct ether_hdr* eth_hdr;
	struct vlan_hdr *vlan_hdr;
	u16 eth_type = 0;
	uint64_t inner_l3_offset = m->l2_len;
	uint64_t ol_flags = m->ol_flags;

	/* Does packet set any of available offloads */
	if (!(ol_flags & HINIC_TX_CKSUM_OFFLOAD_MASK))
		return 0;

	if (unlikely(hinic_validate_tx_offload(m)))
		return -EINVAL;

	if ((ol_flags & PKT_TX_OUTER_IP_CKSUM) ||
			(ol_flags & PKT_TX_OUTER_IPV6) ||
			(ol_flags & PKT_TX_TUNNEL_VXLAN)) {
		inner_l3_offset += m->outer_l2_len + m->outer_l3_len;
		off_info->outer_l2_len = m->outer_l2_len;
		off_info->outer_l3_len = m->outer_l3_len;
		/* just support vxlan tunneling pkt */
		off_info->inner_l2_len = m->l2_len - VXLANLEN -
							sizeof(struct udp_hdr);
		off_info->inner_l3_len = m->l3_len;
		off_info->inner_l4_len = m->l4_len;
		off_info->tunnel_length = m->l2_len;
		off_info->payload_offset = m->outer_l2_len +
			m->outer_l3_len + m->l2_len + m->l3_len + m->l4_len;
		off_info->tunnel_type = TUNNEL_UDP_NO_CSUM;
	} else {
		off_info->inner_l2_len = m->l2_len;
		off_info->inner_l3_len = m->l3_len;
		off_info->inner_l4_len = m->l4_len;
		off_info->tunnel_type = NOT_TUNNEL;
		off_info->payload_offset = m->l2_len + m->l3_len + m->l4_len;
	}

	/* invalid udp or tcp header */
	if (unlikely(off_info->payload_offset > MAX_PLD_OFFSET))
		return -EINVAL;

	/* Process outter udp pseudo-header checksum */
	if ((ol_flags & PKT_TX_TUNNEL_VXLAN) && ((ol_flags & PKT_TX_TCP_SEG) ||
			(ol_flags & PKT_TX_OUTER_IP_CKSUM) ||
			(ol_flags & PKT_TX_OUTER_IPV6))) {
		off_info->tunnel_type = TUNNEL_UDP_CSUM;

		/* inner_l4_tcp_udp csum should be setted to calculate outter
		 * udp checksum when vxlan packets without inner l3 and l4
	 	 */
		off_info->inner_l4_tcp_udp = 1;

		eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
		eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

		if (ETHER_TYPE_VLAN == eth_type) {
			vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
			eth_type = rte_be_to_cpu_16(vlan_hdr->eth_proto);
		}

		if (ETHER_TYPE_IPv4 == eth_type) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
							   m->outer_l2_len);
			off_info->outer_l3_type = IPV4_PKT_WITH_CHKSUM_OFFLOAD;
			ipv4_hdr->hdr_checksum = 0;

			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
					m->outer_l3_len);
			udp_hdr->dgram_cksum = hinic_ipv4_phdr_cksum(ipv4_hdr,
					ol_flags);
		} else if (ETHER_TYPE_IPv6 == eth_type) {
			off_info->outer_l3_type = IPV6_PKT;
			ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
							   m->outer_l2_len);

			udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *,
							  m->outer_l2_len +
							  m->outer_l3_len);
			udp_hdr->dgram_cksum =
				hinic_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
		}
	}

	if (ol_flags & PKT_TX_IPV4)
		off_info->inner_l3_type = (ol_flags & PKT_TX_IP_CKSUM) ?
					IPV4_PKT_WITH_CHKSUM_OFFLOAD :
					IPV4_PKT_NO_CHKSUM_OFFLOAD;
	else if (ol_flags & PKT_TX_IPV6)
		off_info->inner_l3_type = IPV6_PKT;

	/* Process the pseudo-header checksum */
	if ((ol_flags & PKT_TX_UDP_CKSUM) == PKT_TX_UDP_CKSUM) {
		if (ol_flags & PKT_TX_IPV4) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
							   inner_l3_offset);

			if (ol_flags & PKT_TX_IP_CKSUM)
				ipv4_hdr->hdr_checksum = 0;

			udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr +
								m->l3_len);
			udp_hdr->dgram_cksum = hinic_ipv4_phdr_cksum(ipv4_hdr,
								     ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
							   inner_l3_offset);

			udp_hdr = rte_pktmbuf_mtod_offset(m, struct udp_hdr *,
							  inner_l3_offset +
							  m->l3_len);
			udp_hdr->dgram_cksum =
				hinic_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
		}

		off_info->inner_l4_type = UDP_OFFLOAD_ENABLE;
		off_info->inner_l4_tcp_udp = 1;
	} else if ((ol_flags & PKT_TX_TCP_CKSUM) ||
			(ol_flags & PKT_TX_TCP_SEG)) {
		if (ol_flags & PKT_TX_IPV4) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
							   inner_l3_offset);

			if (ol_flags & PKT_TX_IP_CKSUM)
				ipv4_hdr->hdr_checksum = 0;

			/* non-TSO tcp */
			tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr +
								m->l3_len);
			tcp_hdr->cksum =
				hinic_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
							   inner_l3_offset);
			/* non-TSO tcp */
			tcp_hdr = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *,
							  inner_l3_offset +
							  m->l3_len);
			tcp_hdr->cksum =
				hinic_ipv6_phdr_cksum(ipv6_hdr, ol_flags);
		}

		off_info->inner_l4_type = TCP_OFFLOAD_ENABLE;
		off_info->inner_l4_tcp_udp = 1;
	}

	return 0;
}

static inline bool hinic_get_sge_txoff_info(struct rte_mbuf *mbuf_pkt,
					    struct hinic_wqe_info *sqe_info,
					    struct hinic_tx_offload_info
					    *off_info)
{
	u16  i, total_len, sge_cnt = mbuf_pkt->nb_segs;
	struct rte_mbuf *mbuf;
	int ret;

	ret = hinic_tx_offload_pkt_prepare(mbuf_pkt, off_info);
	if (unlikely(ret))
		return false;

	sqe_info->cpy_mbuf_cnt = 0;

	/* non tso mbuf */
	if (likely(!(mbuf_pkt->ol_flags & PKT_TX_TCP_SEG))) {
		if (unlikely(mbuf_pkt->pkt_len > MAX_SINGLE_SGE_SIZE)) {
			/* non tso packet len must less than 64KB */
			return false;
		} else if (unlikely(HINIC_NONTSO_SEG_NUM_INVAILD(sge_cnt))) {
			/* non tso packet buffer number must less than 17
			 * the mbuf segs more than 17 must copy to one buffer */
			total_len = 0;
			mbuf = mbuf_pkt;
			for (i = 0; i < (HINIC_NONTSO_PKT_MAX_SGE - 1) ; i++) {
				total_len += mbuf->data_len;
				mbuf = mbuf->next;
			}

			/* default support copy total 4k mbuf segs */
			if ((u32)(total_len + (u16)HINIC_COPY_MBUF_SIZE) <
				  mbuf_pkt->pkt_len)
				return false;

			sqe_info->sge_cnt = HINIC_NONTSO_PKT_MAX_SGE;
			sqe_info->cpy_mbuf_cnt = 1;
			return true;
		} else {
			/* valid non tso mbuf */
			sqe_info->sge_cnt = sge_cnt;
			return true;
		}
	} else {
		/* tso mbuf */
		if (unlikely(HINIC_TSO_SEG_NUM_INVAILD(sge_cnt))) {
			/* too many mbuf segs */
			return false;
		} else {
			/* check tso mbuf segs are valid or not */
			if (unlikely(!hinic_is_tso_sge_valid(mbuf_pkt,
				     off_info, sqe_info))) {
				/* combination of some tso mbuf segs are invalid */
				return false;
			}

			/* valid tso mbuf */
			return true;
		}
	}
}

static inline void hinic_sq_write_db(struct hinic_sq *sq, int cos)
{
	u16 prod_idx;
	u32 hi_prod_idx;
	struct hinic_sq_db sq_db;

	prod_idx = MASKED_SQ_IDX(sq, sq->wq->prod_idx);
	hi_prod_idx = SQ_DB_PI_HIGH(prod_idx);

	sq_db.db_info = SQ_DB_INFO_SET(hi_prod_idx, HI_PI) |
			SQ_DB_INFO_SET(SQ_DB, TYPE) |
			SQ_DB_INFO_SET(SQ_CFLAG_DP, CFLAG) |
			SQ_DB_INFO_SET(cos, COS) |
			SQ_DB_INFO_SET(sq->q_id, QID);

	/* Data should be written to HW in Big Endian Format */
	sq_db.db_info = cpu_to_be32(sq_db.db_info);

	/* Write all before the doorbell */
	wmb();
	writel(sq_db.db_info, SQ_DB_ADDR(sq, prod_idx));
}

u16 hinic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, u16 nb_pkts)
{
	int free_wqebb_cnt, wqe_wqebb_cnt;
	u32 queue_info, tx_bytes = 0;
	u16 nb_tx;
	struct hinic_wqe_info sqe_info;
	struct hinic_tx_offload_info off_info = { 0 };
	struct rte_mbuf *mbuf_pkt;
	struct hinic_txq *txq;
	struct hinic_tx_info *tx_info;
	struct hinic_sq_wqe *sq_wqe;
	struct hinic_sq_task *task;

#ifdef HINIC_XSTAT_PROF_TX
	uint64_t t1, t2;

	t1 = rte_get_tsc_cycles();
#endif

	txq = (struct hinic_txq *)tx_queue;

	/* PF: walk around hw still fetch packets from sq when mac is linkdown */
	/* VF: alway linkup only check stopped or not */
	if (unlikely(!txq->nic_dev->link_status))
		return 0;

	/* reclaim tx mbuf before xmit new packet */
	if (HINIC_GET_SQ_FREE_WQEBBS(txq) < txq->tx_free_thresh)
		hinic_xmit_mbuf_cleanup(txq);

	/* tx loop routine */
	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		mbuf_pkt = *tx_pkts++;
		queue_info = 0;

		/* 1. parse sge and tx offlod info from mbuf */
		if (unlikely(!hinic_get_sge_txoff_info(mbuf_pkt,
						       &sqe_info, &off_info))) {
			txq->txq_stats.off_errs++;
			break;
		}

		/* 2. try to get enough wqebb */
		wqe_wqebb_cnt = HINIC_SQ_WQEBB_CNT(sqe_info.sge_cnt);
		free_wqebb_cnt = HINIC_GET_SQ_FREE_WQEBBS(txq);
		if (unlikely(wqe_wqebb_cnt > free_wqebb_cnt)) {
			/* reclaim again */
			hinic_xmit_mbuf_cleanup(txq);
			free_wqebb_cnt = HINIC_GET_SQ_FREE_WQEBBS(txq);
			if (unlikely(wqe_wqebb_cnt > free_wqebb_cnt)) {
				txq->txq_stats.tx_busy += (nb_pkts - nb_tx);
				break;
			}
		}

		/* 3. get sq tail wqe address from wqe_page,
		 * sq have enough wqebb for this packet */
		sq_wqe = hinic_get_sq_wqe(txq, wqe_wqebb_cnt, &sqe_info);

		/* 4. fill sq wqe sge section */
		if (unlikely(!hinic_mbuf_dma_map_sge(txq, mbuf_pkt,
						     sq_wqe->buf_descs,
						     &sqe_info))) {
			hinic_return_sq_wqe(txq->nic_dev->hwdev, txq->q_id,
					    wqe_wqebb_cnt, sqe_info.owner);
			txq->txq_stats.off_errs++;
			break;
		}

		/* 5. fill sq wqe task section and queue info */
		task = &sq_wqe->task;

		/* tx packet offload configure */
		hinic_fill_tx_offload_info(mbuf_pkt, task, &queue_info,
					   &off_info);

		/* 6. record tx info */
		tx_info = &txq->tx_info[sqe_info.pi];
		tx_info->mbuf = mbuf_pkt;
		tx_info->wqebb_cnt = wqe_wqebb_cnt;

		/* 7. fill sq wqe header section */
		hinic_fill_sq_wqe_header(&sq_wqe->ctrl, queue_info,
					 sqe_info.sge_cnt, sqe_info.owner);

		/* 8.convert continue or bottom wqe byteorder to big endian */
		hinic_sq_wqe_cpu_to_be32(sq_wqe, sqe_info.seq_wqebbs);

		tx_bytes += mbuf_pkt->pkt_len;
	}

	/* 9. write sq doorbell in burst mode */
	if (nb_tx) {
		hinic_sq_write_db(txq->sq, txq->cos);

		txq->txq_stats.packets += nb_tx;
		txq->txq_stats.bytes += tx_bytes;
	}

#ifdef HINIC_XSTAT_PROF_TX
	/* do profiling stats */
	t2 = rte_get_tsc_cycles();
	txq->txq_stats.app_tsc = t1 - txq->prof_tx_end_tsc;
	txq->prof_tx_end_tsc = t2;
	txq->txq_stats.pmd_tsc = t2 - t1;
	txq->txq_stats.burst_pkts = nb_tx;
#endif

	return nb_tx;
}

void hinic_free_all_tx_skbs(struct hinic_txq *txq)
{
	u16 ci;
	hinic_nic_dev *nic_dev = txq->nic_dev;
	struct hinic_tx_info *tx_info;
	int free_wqebbs = hinic_get_sq_free_wqebbs(nic_dev->hwdev,
						   txq->q_id) + 1;

	while (free_wqebbs < txq->q_depth) {
		ci = hinic_get_sq_local_ci(nic_dev->hwdev, txq->q_id);

		tx_info = &txq->tx_info[ci];

		if (unlikely(tx_info->cpy_mbuf != NULL)) {
			rte_pktmbuf_free(tx_info->cpy_mbuf);
			tx_info->cpy_mbuf = NULL;
		}

		rte_pktmbuf_free(tx_info->mbuf);
		hinic_update_sq_local_ci(nic_dev->hwdev, txq->q_id,
					 tx_info->wqebb_cnt);

		free_wqebbs += tx_info->wqebb_cnt;
		tx_info->mbuf = NULL;
	}
}

void hinic_free_all_tx_resources(struct rte_eth_dev *eth_dev)
{
	u16 q_id;
	hinic_nic_dev *nic_dev =
		(hinic_nic_dev *)HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);

	for (q_id = 0; q_id < nic_dev->num_sq; q_id++) {
		eth_dev->data->tx_queues[q_id] = NULL;

		if (nic_dev->txqs[q_id] == NULL)
			continue;

		/* stop tx queue free tx mbuf */
		hinic_free_all_tx_skbs(nic_dev->txqs[q_id]);
		hinic_free_tx_resources(nic_dev->txqs[q_id]);

		/* free txq */
		kfree(nic_dev->txqs[q_id]);
		nic_dev->txqs[q_id] = NULL;
	}
}

void hinic_free_all_tx_mbuf(struct rte_eth_dev *eth_dev)
{
	u16 q_id;
	hinic_nic_dev *nic_dev =
		(hinic_nic_dev *)HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);

	for (q_id = 0; q_id < nic_dev->num_sq; q_id++)
		/* stop tx queue free tx mbuf */
		hinic_free_all_tx_skbs(nic_dev->txqs[q_id]);
}

int hinic_setup_tx_resources(struct hinic_txq *txq)
{
	u64 tx_info_sz;

	tx_info_sz = txq->q_depth * sizeof(*txq->tx_info);
	txq->tx_info = (struct hinic_tx_info *)
		kzalloc_aligned(tx_info_sz, GFP_KERNEL);
	if (!txq->tx_info) {
		dev_err(NULL, "Allocate tx info failed\n");
		return -ENOMEM;
	}

	return HINIC_OK;
}

void hinic_free_tx_resources(struct hinic_txq *txq)
{
	if (txq->tx_info == NULL)
		return;

	kfree(txq->tx_info);
	txq->tx_info = NULL;
}
