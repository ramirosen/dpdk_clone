/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "hinic_pmd_ethdev.h"
#include "hinic_pmd_rx.h"

#ifdef HINIC_XSTAT_RXBUF_INFO
static void hinic_rxq_buffer_done_count(struct hinic_rxq *rxq)
{
	u16 sw_ci, avail_pkts = 0, hit_done = 0, cqe_hole = 0;
	u32 status;
	volatile struct hinic_rq_cqe *rx_cqe;

	for (sw_ci = 0; sw_ci < rxq->q_depth; sw_ci++) {
		rx_cqe = &rxq->rx_cqe[sw_ci];

		/* test current ci is done */
		status = rx_cqe->status;
		if (!HINIC_GET_RX_DONE_BE(status)) {
			if (hit_done) {
				cqe_hole++;
				hit_done = 0;
			}
			continue;
		}

		avail_pkts++;
		hit_done = 1;
	}

	rxq->rxq_stats.rx_avail = avail_pkts;
	rxq->rxq_stats.rx_hole = cqe_hole;
}
#endif

void hinic_rxq_get_stats(struct hinic_rxq *rxq, struct hinic_rxq_stats *stats)
{
	if (!rxq || !stats)
		return;

#ifdef HINIC_XSTAT_RXBUF_INFO
	rxq->rxq_stats.rx_mbuf = (rxq->q_depth)
				- HINIC_GET_RQ_FREE_WQEBBS(rxq);

	hinic_rxq_buffer_done_count(rxq);
#endif
#ifdef HINIC_XSTAT_MBUF_USE
	rxq->rxq_stats.left_mbuf = rxq->rxq_stats.alloc_mbuf
				- rxq->rxq_stats.free_mbuf;
#endif
	memcpy(stats, &rxq->rxq_stats, sizeof(rxq->rxq_stats));
}

void hinic_rxq_stats_reset(struct hinic_rxq *rxq)
{
	struct hinic_rxq_stats *rxq_stats;

	if (rxq == NULL)
		return;

	rxq_stats = &rxq->rxq_stats;
	memset(rxq_stats, 0, sizeof(*rxq_stats));
}

/* mbuf alloc and free */
static inline struct rte_mbuf *hinic_rte_rxmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m  = rte_mbuf_raw_alloc(mp);
	return m;
}

static int hinic_rx_alloc_cqe(struct hinic_rxq *rxq)
{
	size_t cqe_mem_size;

	/* allocate continuous cqe memory for saving number of memory zone */
	cqe_mem_size = sizeof(struct hinic_rq_cqe) * rxq->q_depth;
	rxq->cqe_start_vaddr = dma_zalloc_coherent(rxq->nic_dev, cqe_mem_size,
						   &rxq->cqe_start_paddr,
						   GFP_KERNEL);
	if (!rxq->cqe_start_vaddr) {
		dev_err(rxq->nic_dev, "Allocate cqe dma memory failed\n");
		return -ENOMEM;
	}

	rxq->rx_cqe = (struct hinic_rq_cqe *)rxq->cqe_start_vaddr;

	return HINIC_OK;
}

static void hinic_rx_free_cqe(struct hinic_rxq *rxq)
{
	size_t cqe_mem_size;

	cqe_mem_size = sizeof(struct hinic_rq_cqe) * rxq->q_depth;
	dma_free_coherent(rxq->nic_dev, cqe_mem_size,
			  rxq->cqe_start_vaddr,
			  rxq->cqe_start_paddr);
	rxq->cqe_start_vaddr = NULL;
}

static int hinic_rx_fill_wqe(struct hinic_rxq *rxq)
{
	hinic_nic_dev *nic_dev = rxq->nic_dev;
	struct hinic_rq_wqe *rq_wqe;
	dma_addr_t buf_dma_addr, cqe_dma_addr;
	u16 pi = 0;
	int rq_wqe_len;
	int i;

	buf_dma_addr = 0;
	cqe_dma_addr = rxq->cqe_start_paddr;
	for (i = 0; i < rxq->q_depth; i++) {
		rq_wqe = (struct hinic_rq_wqe *)
			hinic_get_rq_wqe(nic_dev->hwdev, rxq->q_id, &pi);
		if (!rq_wqe) {
			dev_err(nic_dev, "Get rq wqe failed\n");
			break;
		}

		hinic_prepare_rq_wqe(rq_wqe, pi, buf_dma_addr, cqe_dma_addr);
		cqe_dma_addr +=  sizeof(struct hinic_rq_cqe);

		rq_wqe_len = sizeof(struct hinic_rq_wqe);
		hinic_cpu_to_be32(rq_wqe, rq_wqe_len);
	}

	hinic_return_rq_wqe(nic_dev->hwdev, rxq->q_id, i);

	return i;
}

/* alloc cqe and prepare rqe */
int hinic_setup_rx_resources(struct hinic_rxq *rxq)
{
	u64 rx_info_sz;
	int err, pkts;

	rx_info_sz = rxq->q_depth * sizeof(*rxq->rx_info);
	rxq->rx_info = (struct hinic_rx_info *)kzalloc_aligned(rx_info_sz,
							       GFP_KERNEL);
	if (!rxq->rx_info)
		return -ENOMEM;

	err = hinic_rx_alloc_cqe(rxq);
	if (err) {
		pr_err("Allocate rx cqe failed");
		goto rx_cqe_err;
	}

	pkts = hinic_rx_fill_wqe(rxq);
	if (pkts != rxq->q_depth) {
		pr_err("Fill rx wqe failed");
		err = -ENOMEM;
		goto rx_fill_err;
	}

	return 0;

rx_fill_err:
	hinic_rx_free_cqe(rxq);

rx_cqe_err:
	kfree(rxq->rx_info);
	rxq->rx_info = NULL;

	return err;
}

void hinic_free_rx_resources(struct hinic_rxq *rxq)
{
	if (rxq->rx_info == NULL)
		return;

	hinic_rx_free_cqe(rxq);
	kfree(rxq->rx_info);
	rxq->rx_info = NULL;
}

void hinic_free_all_rx_resources(struct rte_eth_dev *eth_dev)
{
	u16 q_id;
	hinic_nic_dev *nic_dev =
		(hinic_nic_dev *)HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);

	for (q_id = 0; q_id < nic_dev->num_rq; q_id++) {
		eth_dev->data->rx_queues[q_id] = NULL;

		if (nic_dev->rxqs[q_id] == NULL)
			continue;

		hinic_free_all_rx_skbs(nic_dev->rxqs[q_id]);
		hinic_free_rx_resources(nic_dev->rxqs[q_id]);
		kfree(nic_dev->rxqs[q_id]);
		nic_dev->rxqs[q_id] = NULL;
	}
}

void hinic_free_all_rx_mbuf(struct rte_eth_dev *eth_dev)
{
	u16 q_id;
	hinic_nic_dev *nic_dev = (hinic_nic_dev *)HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);

	for (q_id = 0; q_id < nic_dev->num_rq; q_id++)
		hinic_free_all_rx_skbs(nic_dev->rxqs[q_id]);
}

static void hinic_recv_jumbo_pkt(struct hinic_rxq *rxq,
				 struct rte_mbuf *head_skb,
				 u32 remain_pkt_len)
{
	hinic_nic_dev *nic_dev = rxq->nic_dev;
	struct rte_mbuf *cur_mbuf, *rxm = NULL;
	struct hinic_rx_info *rx_info;
	u16 sw_ci, rx_buf_len = rxq->buf_len;
	u32 pkt_len;

	while (remain_pkt_len > 0) {
		sw_ci = hinic_get_rq_local_ci(nic_dev->hwdev, rxq->q_id);
		rx_info = &rxq->rx_info[sw_ci];

		hinic_update_rq_local_ci(nic_dev->hwdev, rxq->q_id, 1);

		pkt_len = remain_pkt_len > rx_buf_len ?
			rx_buf_len : remain_pkt_len;
		remain_pkt_len -= pkt_len;

		cur_mbuf = rx_info->mbuf;
		cur_mbuf->data_len = (u16)pkt_len;
		cur_mbuf->next = NULL;

		head_skb->pkt_len += cur_mbuf->data_len;
		head_skb->nb_segs++;
#ifdef HINIC_XSTAT_MBUF_USE
		rxq->rxq_stats.free_mbuf++;
#endif

		if (!rxm)
			head_skb->next = cur_mbuf;
		else
			rxm->next = cur_mbuf;

		rxm = cur_mbuf;
	}
}

static void hinic_rss_deinit(hinic_nic_dev *nic_dev)
{
	u8 prio_tc[HINIC_DCB_UP_MAX] = {0};
	(void)hinic_rss_cfg(nic_dev->hwdev, 0,
			    nic_dev->rss_tmpl_idx, 0, prio_tc);
}

static int hinic_rss_key_init(hinic_nic_dev *nic_dev,
			      struct rte_eth_rss_conf *rss_conf)
{
	u8 default_rss_key[HINIC_RSS_KEY_SIZE] = {
			 0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
			 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
			 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
			 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
			 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};
	u8 hashkey[HINIC_RSS_KEY_SIZE] = {0};
	u8 tmpl_idx = nic_dev->rss_tmpl_idx;

	if (rss_conf->rss_key == NULL)
		memcpy(hashkey, default_rss_key, HINIC_RSS_KEY_SIZE);
	else
		memcpy(hashkey, rss_conf->rss_key, rss_conf->rss_key_len);

	return hinic_rss_set_template_tbl(nic_dev->hwdev, tmpl_idx, hashkey);
}

static void hinic_fill_rss_type(struct nic_rss_type *rss_type,
				struct rte_eth_rss_conf *rss_conf)
{
	u64 rss_hf = rss_conf->rss_hf;

	rss_type->ipv4 = (rss_hf & (ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4)) ? 1 : 0;
	rss_type->tcp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_TCP) ? 1 : 0;
	rss_type->ipv6 = (rss_hf & (ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6)) ? 1 : 0;
	rss_type->ipv6_ext = (rss_hf & ETH_RSS_IPV6_EX) ? 1 : 0;
	rss_type->tcp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_TCP) ? 1 : 0;
	rss_type->tcp_ipv6_ext = (rss_hf & ETH_RSS_IPV6_TCP_EX) ? 1 : 0;
	rss_type->udp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_UDP) ? 1 : 0;
	rss_type->udp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_UDP) ? 1 : 0;
}

static void hinic_fillout_indir_tbl(hinic_nic_dev *nic_dev, u32 *indir)
{
	u8 rss_queue_count = nic_dev->num_rss;
	int i = 0, j;

	if (rss_queue_count == 0) {
		/* delete q_id from indir tbl */
		for (i = 0; i < HINIC_RSS_INDIR_SIZE; i++)
			indir[i] = 0xFF;	/* Invalid value in indir tbl */
	} else {
		while (i < HINIC_RSS_INDIR_SIZE)
			for (j = 0; (j < rss_queue_count) &&
			     (i < HINIC_RSS_INDIR_SIZE); j++)
				indir[i++] = nic_dev->rx_queue_list[j];
	}
}

static int hinic_rss_init(hinic_nic_dev *nic_dev,
			  __attribute__((unused)) u8 *rq2iq_map,
			  struct rte_eth_rss_conf *rss_conf)
{
	u32 indir_tbl[HINIC_RSS_INDIR_SIZE] = {0};
	struct nic_rss_type rss_type = {0};
	u8 prio_tc[HINIC_DCB_UP_MAX] = {0};
	u8 tmpl_idx = 0xFF, num_tc = 0;
	int err;

	tmpl_idx = nic_dev->rss_tmpl_idx;

	err = hinic_rss_key_init(nic_dev, rss_conf);
	if (err)
		return err;

	if (!nic_dev->rss_indir_flag) {
		hinic_fillout_indir_tbl(nic_dev, indir_tbl);
		err = hinic_rss_set_indir_tbl(nic_dev->hwdev, tmpl_idx,
					      indir_tbl);
		if (err)
			return err;
	}

	hinic_fill_rss_type(&rss_type, rss_conf);
	err = hinic_set_rss_type(nic_dev->hwdev, tmpl_idx, rss_type);
	if (err)
		return err;

	err = hinic_rss_set_hash_engine(nic_dev->hwdev, tmpl_idx,
					HINIC_RSS_HASH_ENGINE_TYPE_TOEP);
	if (err)
		return err;

	return hinic_rss_cfg(nic_dev->hwdev, 1, tmpl_idx, num_tc, prio_tc);
}

static void hinic_add_rq_to_rx_queue_list(hinic_nic_dev *nic_dev, u16 queue_id)
{
	u8 rss_queue_count = nic_dev->num_rss;

	RTE_ASSERT(rss_queue_count <= (RTE_DIM(nic_dev->rx_queue_list) - 1));

	nic_dev->rx_queue_list[rss_queue_count] = queue_id;
	nic_dev->num_rss++;
}

/**
 * hinic_setup_num_qps - determine num_qps from rss_tmpl_id
 * @nic_dev: pointer to the private ethernet device
 * Return: 0 on Success, error code otherwise.
 **/
static int hinic_setup_num_qps(hinic_nic_dev *nic_dev)
{
	int err, i;

	if (!(nic_dev->flags & ETH_MQ_RX_RSS_FLAG)) {
		nic_dev->flags &= ~ETH_MQ_RX_RSS_FLAG;
		nic_dev->num_rss = 0;
		if (nic_dev->num_rq > 1) {
			/* get rss template id */
			err = hinic_rss_template_alloc(nic_dev->hwdev,
						       &nic_dev->rss_tmpl_idx);
			if (err) {
				pr_warning("Alloc rss template failed");
				return err;
			}
			nic_dev->flags |= ETH_MQ_RX_RSS_FLAG;
			for (i = 0; i < nic_dev->num_rq; i++)
				hinic_add_rq_to_rx_queue_list(nic_dev, i);
		}
	}

	return 0;
}

static void hinic_destroy_num_qps(hinic_nic_dev *nic_dev)
{
	if (nic_dev->flags & ETH_MQ_RX_RSS_FLAG) {
		if (hinic_rss_template_free(nic_dev->hwdev,
					    nic_dev->rss_tmpl_idx))
			pr_warning("Free rss template failed");

		nic_dev->flags &= ~ETH_MQ_RX_RSS_FLAG;
	}
}

static int hinic_config_mq_rx_rss(hinic_nic_dev *nic_dev, bool on)
{
	int ret = 0;

	if (on) {
		ret = hinic_setup_num_qps(nic_dev);
		if (ret)
			dev_err(nic_dev, "Setup num_qps failed\n");
	} else {
		hinic_destroy_num_qps(nic_dev);
	}

	return ret;
}

int hinic_config_mq_mode(struct rte_eth_dev *dev, bool on)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	int ret = 0;

	switch (dev_conf->rxmode.mq_mode) {
	case ETH_MQ_RX_RSS:
		ret = hinic_config_mq_rx_rss(nic_dev, on);
		break;
	default:
		break;
	}

	return ret;
}

int hinic_rx_configure(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	struct rte_eth_rss_conf rss_conf =
		dev->data->dev_conf.rx_adv_conf.rss_conf;
	int err;

	if (nic_dev->flags & ETH_MQ_RX_RSS_FLAG) {
		if (rss_conf.rss_hf == 0) {
			rss_conf.rss_hf = HINIC_RSS_OFFLOAD_ALL;
		} else if ((rss_conf.rss_hf & HINIC_RSS_OFFLOAD_ALL) == 0) {
			dev_err(nic_dev, "Do not support rss offload all\n");
			goto exit;
		}

		err = hinic_rss_init(nic_dev, NULL, &rss_conf);
		if (err) {
			dev_err(nic_dev, "Init rss failed\n");
			goto exit;
		}
	}

	return 0;
exit:
	hinic_destroy_num_qps(nic_dev);
	return HINIC_ERROR;
}

void hinic_rx_remove_configure(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	if (nic_dev->flags & ETH_MQ_RX_RSS_FLAG) {
		hinic_rss_deinit(nic_dev);
		hinic_destroy_num_qps(nic_dev);
	}
}

void hinic_free_all_rx_skbs(struct hinic_rxq *rxq)
{
	hinic_nic_dev *nic_dev = (hinic_nic_dev *)rxq->nic_dev;
	struct hinic_rx_info *rx_info;
	int free_wqebbs =
		hinic_get_rq_free_wqebbs(nic_dev->hwdev, rxq->q_id) + 1;
	volatile struct hinic_rq_cqe *rx_cqe;
	u16 ci;

	while (free_wqebbs++ < rxq->q_depth) {
		ci = hinic_get_rq_local_ci(nic_dev->hwdev, rxq->q_id);

		rx_cqe = &rxq->rx_cqe[ci];

		/* clear done bit */
		rx_cqe->status = 0;

		rx_info = &rxq->rx_info[ci];
#ifdef HINIC_XSTAT_MBUF_USE
		hinic_rx_free_mbuf(rxq, rx_info->mbuf);
#else
		hinic_rx_free_mbuf(rx_info->mbuf);
#endif
		rx_info->mbuf = NULL;

		hinic_update_rq_local_ci(nic_dev->hwdev, rxq->q_id, 1);
	}
}

static inline struct hinic_rq_wqe *hinic_get_rearm_rq_wqe(struct hinic_rxq *rxq,
							  u16 *prod_idx)
{
	u32 cur_pi;
	struct hinic_wq *wq = rxq->wq;

	/* record current pi */
	cur_pi = MASKED_WQE_IDX(wq, wq->prod_idx);

	/* update next pi and delta */
	wq->prod_idx += 1;
	wq->delta -= 1;

	/* return current pi */
	*prod_idx = cur_pi;
	return (struct hinic_rq_wqe *)WQ_WQE_ADDR(wq, cur_pi);
}

/* performance: byteorder swap m128i */
static inline void hinic_rq_cqe_be_to_cpu32(void *dst_le32,
					    volatile void *src_be32)
{
	volatile __m128i *wqe_be = (volatile __m128i *)src_be32;
	__m128i *wqe_le = (__m128i *)dst_le32;
	__m128i shuf_mask =  _mm_set_epi8(12, 13, 14, 15, 8, 9, 10,
					  11, 4, 5, 6, 7, 0, 1, 2, 3);

	/* swap 32B CQE using 2 128 bits instructions */
	wqe_le[0] = _mm_shuffle_epi8(wqe_be[0], shuf_mask);
}

static inline uint64_t hinic_rx_rss_hash(uint32_t offload_type,
					 uint32_t cqe_hass_val,
					 uint32_t *rss_hash)
{
	uint32_t rss_type;

	rss_type = HINIC_GET_RSS_TYPES(offload_type);
	if (likely(0 != rss_type)) {
		*rss_hash = cqe_hass_val;
		return PKT_RX_RSS_HASH;
	}

	return 0;
}

static inline uint64_t hinic_rx_csum(uint32_t status, struct hinic_rxq *rxq)
{
	uint32_t checksum_err;
	uint64_t flags;

	/* most case checksum is ok */
	checksum_err = HINIC_GET_RX_CSUM_ERR(status);
	if (likely(checksum_err == 0))
		return (PKT_RX_IP_CKSUM_GOOD | PKT_RX_L4_CKSUM_GOOD);

	/* If BYPASS bit set, all other status indications should be ignored */
	if (unlikely(HINIC_CSUM_ERR_BYPASSED(checksum_err)))
		return PKT_RX_IP_CKSUM_UNKNOWN;

	flags = 0;

	/* IP checksum error */
	if (HINIC_CSUM_ERR_IP(checksum_err))
		flags |= PKT_RX_IP_CKSUM_BAD;

	/* L4 checksum error */
	if (HINIC_CSUM_ERR_L4(checksum_err))
		flags |= PKT_RX_L4_CKSUM_BAD;

	rxq->rxq_stats.errors++;

	return flags;
}

static inline uint64_t hinic_rx_vlan(uint32_t offload_type, uint32_t vlan_len,
				     uint16_t *vlan_tci)
{
	uint16_t vlan_tag;

	vlan_tag = HINIC_GET_RX_VLAN_TAG(vlan_len);
	if (!HINIC_GET_RX_VLAN_OFFLOAD_EN(offload_type) || 0 == vlan_tag) {
		*vlan_tci = 0;
		return 0;
	}

	*vlan_tci = vlan_tag;

	return PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
}

static inline uint64_t hinic_rx_pkt_type(uint32_t offload_type)
{
	uint32_t pkt_type, pkt_idx;
	static const uint32_t pkt_type_table[RQ_CQE_PKT_TYPES_L2_MASK + 1]
	__rte_cache_aligned = {
		[3] =  RTE_PTYPE_L3_IPV4,
		[4] =  RTE_PTYPE_L3_IPV4_EXT,
		[5] =  RTE_PTYPE_L4_FRAG,
		[7] =  RTE_PTYPE_L3_IPV6,
		[9] =  RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_SCTP,
		[10] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP,
		[11] = RTE_PTYPE_TUNNEL_VXLAN,
		[13] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
		[14] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
		[15] = RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_TCP,
		[16] = RTE_PTYPE_TUNNEL_NVGRE,
		[65] = RTE_PTYPE_L4_ICMP,
		[66] = RTE_PTYPE_L4_ICMP,
		[76] = RTE_PTYPE_L2_ETHER_LLDP,
		[81] = RTE_PTYPE_L2_ETHER_ARP,
		/* All others reserved */
	};
	pkt_idx = HINIC_GET_PKT_TYPES(offload_type);

	/* Unknown type */
	if (unlikely(pkt_idx == 0))
		return RTE_PTYPE_UNKNOWN;

	/* if hardware report index not correct set l2 ether as default */
	pkt_type = RTE_PTYPE_L2_ETHER;
	pkt_type |= pkt_type_table[HINIC_PKT_TYPES_L2(pkt_idx)];

	return pkt_type;
}

static inline u32 hinic_rx_alloc_mbuf_bulk(struct hinic_rxq *rxq,
					   struct rte_mbuf **mbufs,
					   u32 exp_mbuf_cnt)
{
	int rc;
	u32 avail_cnt;

	rc = rte_pktmbuf_alloc_bulk(rxq->mb_pool, mbufs, exp_mbuf_cnt);
	if (likely(rc == HINIC_OK)) {
		avail_cnt = exp_mbuf_cnt;
	} else {
		avail_cnt = 0;
		rxq->rxq_stats.rx_nombuf += exp_mbuf_cnt;
	}
#ifdef HINIC_XSTAT_MBUF_USE
	rxq->rxq_stats.alloc_mbuf += avail_cnt;
#endif
	return avail_cnt;
}

#ifdef HINIC_XSTAT_MBUF_USE
void hinic_rx_free_mbuf(struct hinic_rxq *rxq, struct rte_mbuf *m)
{
	rte_pktmbuf_free(m);
	rxq->rxq_stats.free_mbuf++;
}
#else
void hinic_rx_free_mbuf(struct rte_mbuf *m)
{
	rte_pktmbuf_free(m);
}
#endif

static struct rte_mbuf *hinic_rx_alloc_mbuf(struct hinic_rxq *rxq,
					dma_addr_t *dma_addr)
{
	struct rte_mbuf *mbuf;

	mbuf = hinic_rte_rxmbuf_alloc(rxq->mb_pool);
	if (unlikely(!mbuf))
		return NULL;

	*dma_addr = rte_mbuf_data_iova_default(mbuf);

#ifdef HINIC_XSTAT_MBUF_USE
	rxq->rxq_stats.alloc_mbuf++;
#endif

	return mbuf;
}

static inline void hinic_rearm_rxq_mbuf(struct hinic_rxq *rxq)
{
	u16 pi;
	u32 i, free_wqebbs, rearm_wqebbs, exp_wqebbs;
	dma_addr_t dma_addr;
	struct hinic_rq_wqe *rq_wqe;
	struct rte_mbuf **rearm_mbufs;

	/* check free wqebb fo rearm */
	free_wqebbs = HINIC_GET_RQ_FREE_WQEBBS(rxq);
	if (unlikely(free_wqebbs < rxq->rx_free_thresh))
		return;

	/* get rearm mbuf array */
	pi = HINIC_GET_RQ_LOCAL_PI(rxq);
	rearm_mbufs = (struct rte_mbuf**)(&rxq->rx_info[pi]);

	/* check rxq free wqebbs turn around */
	if (unlikely(pi > rxq->rxinfo_align_end))
		exp_wqebbs = rxq->q_depth - pi;
	else
		exp_wqebbs = rxq->rx_free_thresh;

	/* alloc mbuf in bulk */
	rearm_wqebbs = hinic_rx_alloc_mbuf_bulk(rxq, rearm_mbufs, exp_wqebbs);
	if (unlikely(0 == rearm_wqebbs))
		return;

	/* rearm rx mbuf */
	rq_wqe = (struct hinic_rq_wqe *)WQ_WQE_ADDR(rxq->wq, pi);
	for (i = 0; i < rearm_wqebbs; i++) {
		dma_addr = rte_mbuf_data_iova_default(rearm_mbufs[i]);
		rq_wqe->buf_desc.addr_high =
					cpu_to_be32(upper_32_bits(dma_addr));
		rq_wqe->buf_desc.addr_low =
					cpu_to_be32(lower_32_bits(dma_addr));
		rq_wqe++;
	}
	rxq->wq->prod_idx += rearm_wqebbs;
	rxq->wq->delta -= rearm_wqebbs;

	/* update rq hw_pi */
	wmb();
	HINIC_UPDATE_RQ_HW_PI(rxq, pi + rearm_wqebbs);
}

void hinic_rx_alloc_pkts(struct hinic_rxq *rxq)
{
	hinic_nic_dev *nic_dev = rxq->nic_dev;
	struct hinic_rq_wqe *rq_wqe;
	struct hinic_rx_info *rx_info;
	struct rte_mbuf *skb;
	dma_addr_t dma_addr;
	u16 pi = 0;
	int i, free_wqebbs;

	free_wqebbs = HINIC_GET_RQ_FREE_WQEBBS(rxq);
	for (i = 0; i < free_wqebbs; i++) {
		skb = hinic_rx_alloc_mbuf(rxq, &dma_addr);
		if (unlikely(!skb)) {
			rxq->rxq_stats.rx_nombuf++;
			break;
		}

		rq_wqe = (struct hinic_rq_wqe *)
			hinic_get_rq_wqe(nic_dev->hwdev, rxq->q_id, &pi);
		if (unlikely(!rq_wqe)) {
#ifdef HINIC_XSTAT_MBUF_USE
			hinic_rx_free_mbuf(rxq, skb);
#else
			hinic_rx_free_mbuf(skb);
#endif
			break;
		}

		/* fill buffer address only */
		rq_wqe->buf_desc.addr_high =
				cpu_to_be32(upper_32_bits(dma_addr));
		rq_wqe->buf_desc.addr_low =
				cpu_to_be32(lower_32_bits(dma_addr));

		rx_info = &rxq->rx_info[pi];
		rx_info->mbuf = skb;
	}

	if (likely(i > 0)) {
		wmb();
		HINIC_UPDATE_RQ_HW_PI(rxq, pi + 1);
	}
}

u16 hinic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, u16 nb_pkts)
{
	struct rte_mbuf *rxm;
	struct hinic_rxq *rxq = (struct hinic_rxq *)rx_queue;
	struct hinic_rx_info *rx_info;
	volatile struct hinic_rq_cqe *rx_cqe;
	u16 rx_buf_len, pkts = 0;
	u16 sw_ci, ci_mask, wqebb_cnt = 0;
	u32 pkt_len, status, vlan_len;
	u64 rx_bytes = 0;
#ifdef HINIC_XSTAT_PROF_RX
	uint64_t t1 = rte_get_tsc_cycles();
	uint64_t t2;
#endif
	struct hinic_rq_cqe cqe;
	u32 offload_type, rss_hash;

	rx_buf_len = rxq->buf_len;

	/* 1. get polling start ci */
	ci_mask = HINIC_GET_RQ_WQE_MASK(rxq);
	sw_ci = HINIC_GET_RQ_LOCAL_CI(rxq);

	while (pkts < nb_pkts) {
		 /* 2. current ci is done */
		rx_cqe = &rxq->rx_cqe[sw_ci];
		status = rx_cqe->status;
		if (!HINIC_GET_RX_DONE_BE(status))
			break;

	        /* read other cqe member after status */
	        rmb();

		/* convert cqe and get packet length */
		hinic_rq_cqe_be_to_cpu32(&cqe, (volatile void *)rx_cqe);
		vlan_len = cqe.vlan_len;

		rx_info = &rxq->rx_info[sw_ci];
		rxm = rx_info->mbuf;

		/* 3. next ci point and prefetch */
		sw_ci++;
		sw_ci &= ci_mask;

		/* prefetch next mbuf first 64B */
		rte_prefetch0(rxq->rx_info[sw_ci].mbuf);

		/* 4. jumbo frame process */
		pkt_len = HINIC_GET_RX_PKT_LEN(vlan_len);
		if (likely(pkt_len <= rx_buf_len)) {
			rxm->data_len = pkt_len;
			rxm->pkt_len = pkt_len;
			wqebb_cnt++;
		} else {
			rxm->data_len = rx_buf_len;
			rxm->pkt_len = rx_buf_len;

			/* if jumbo use multi-wqebb update ci,
			 * recv_jumbo_pkt will also update ci
			 */
			HINIC_UPDATE_RQ_LOCAL_CI(rxq, wqebb_cnt + 1);
			wqebb_cnt = 0;
			hinic_recv_jumbo_pkt(rxq, rxm, pkt_len - rx_buf_len);
			sw_ci = HINIC_GET_RQ_LOCAL_CI(rxq);
		}

		/* 5. vlan/checksum/rss/pkt_type/gro offload */
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->port = rxq->port_id;
		offload_type = cqe.offload_type;

		/* vlan offload */
		rxm->ol_flags |= hinic_rx_vlan(offload_type, vlan_len,
					       &rxm->vlan_tci);

		/* checksum offload */
		rxm->ol_flags |= hinic_rx_csum(cqe.status, rxq);

		/* rss hash offload */
		rss_hash = cqe.rss_hash;
		rxm->ol_flags |= hinic_rx_rss_hash(offload_type, rss_hash,
						   &rxm->hash.rss);

		/* packet type parser offload */
		rxm->packet_type = hinic_rx_pkt_type(offload_type);

		/* 6. clear done bit */
		rx_cqe->status = 0;

		rx_bytes += pkt_len;
		rx_pkts[pkts++] = rxm;
	}

	if (pkts) {
		/* 7. update ci */
		HINIC_UPDATE_RQ_LOCAL_CI(rxq, wqebb_cnt);

		/* do packet stats */
		rxq->rxq_stats.packets += pkts;
		rxq->rxq_stats.bytes += rx_bytes;
#ifdef HINIC_XSTAT_MBUF_USE
		rxq->rxq_stats.free_mbuf += pkts;
#endif
	}

#ifdef HINIC_XSTAT_RXBUF_INFO
	rxq->rxq_stats.burst_pkts = pkts;
#endif

	/* 8. rearm mbuf to rxq */
	hinic_rearm_rxq_mbuf(rxq);

#ifdef HINIC_XSTAT_PROF_RX
	/* do profiling stats */
	t2 = rte_get_tsc_cycles();
	rxq->rxq_stats.app_tsc = t1 - rxq->prof_rx_end_tsc;
	rxq->prof_rx_end_tsc = t2;
	rxq->rxq_stats.pmd_tsc = t2 - t1;
#endif

	return pkts;
}
