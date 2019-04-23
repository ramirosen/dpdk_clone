/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_ETHDEV_H_
#define _HINIC_PMD_ETHDEV_H_

#include "base/hinic_pmd_dpdev.h"

#define PMD_DRIVER_VERSION	"2.0.0.0"

/* Vendor ID used by Huawei devices */
#define HINIC_HUAWEI_VENDOR_ID 0x19E5

/* Hinic devices */
#define HINIC_DEV_ID_PRD		0x1822
#define HINIC_DEV_ID_MEZZ_25GE		0x0210
#define HINIC_DEV_ID_MEZZ_40GE		0x020D
#define HINIC_DEV_ID_MEZZ_100GE		0x0205

#define HINIC_PMD_DEV_BOND			(1)
#define HINIC_PMD_DEV_EMPTY			(-1)
#define HINIC_DEV_NAME_MAX_LEN	(32)

#define HINIC_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_FRAG_IPV4 |\
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_IPV6 | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_IPV6_EX | \
	ETH_RSS_IPV6_TCP_EX | \
	ETH_RSS_IPV6_UDP_EX)

#define HINIC_MTU_TO_PKTLEN(mtu)	\
	((mtu) + ETH_HLEN + ETH_CRC_LEN)

#define HINIC_PKTLEN_TO_MTU(pktlen)	\
	((pktlen) - (ETH_HLEN + ETH_CRC_LEN))

/* vhd type */
#define HINIC_VHD_TYPE_0B		(2)
#define HINIC_VHD_TYPE_10B		(1)
#define HINIC_VHD_TYPE_12B		(0)

/* vlan_id is a 12 bit number.
 * The VFTA array is actually a 4096 bit array, 128 of 32bit elements.
 * 2^5 = 32. The val of lower 5 bits specifies the bit in the 32bit element.
 * The higher 7 bit val specifies VFTA array index.
 */
#define HINIC_VFTA_BIT(vlan_id)    (1 << ((vlan_id) & 0x1F))
#define HINIC_VFTA_IDX(vlan_id)    ((vlan_id) >> 5)

#define HINIC_INTR_CB_UNREG_MAX_RETRIES		10

/* eth_dev ops */
int hinic_dev_configure(struct rte_eth_dev *dev);
void hinic_dev_infos_get(struct rte_eth_dev *dev,
			 struct rte_eth_dev_info *dev_info);
int hinic_dev_start(struct rte_eth_dev *dev);
int hinic_link_update(struct rte_eth_dev *dev, int wait_to_complete);
void hinic_rx_queue_release(void *queue);
void hinic_tx_queue_release(void *queue);
void hinic_dev_stop(struct rte_eth_dev *dev);
void hinic_dev_close(struct rte_eth_dev *dev);
int hinic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats);
void hinic_dev_stats_reset(struct rte_eth_dev *dev);
void hinic_dev_xstats_reset(struct rte_eth_dev *dev);
void hinic_dev_promiscuous_enable(struct rte_eth_dev *dev);
void hinic_dev_promiscuous_disable(struct rte_eth_dev *dev);

int hinic_vlan_offload_set(struct rte_eth_dev *dev, int mask);
int hinic_dev_atomic_write_link_status(struct rte_eth_dev *dev,
				       struct rte_eth_link *link);
int hinic_dev_atomic_read_link_status(struct rte_eth_dev *dev,
				      struct rte_eth_link *link);
int hinic_link_event_process(struct rte_eth_dev *dev, u8 status);
void hinic_disable_interrupt(struct rte_eth_dev *dev);
void hinic_free_all_sq(hinic_nic_dev *nic_dev);
void hinic_free_all_rq(hinic_nic_dev *nic_dev);

int hinic_rxtx_configure(struct rte_eth_dev *dev);
int hinic_rss_hash_update(struct rte_eth_dev *dev,
			  struct rte_eth_rss_conf *rss_conf);
int hinic_rss_conf_get(struct rte_eth_dev *dev,
		       struct rte_eth_rss_conf *rss_conf);
int hinic_rss_indirtbl_update(struct rte_eth_dev *dev,
			      struct rte_eth_rss_reta_entry64 *reta_conf,
			      uint16_t reta_size);
int hinic_rss_indirtbl_query(struct rte_eth_dev *dev,
			     struct rte_eth_rss_reta_entry64 *reta_conf,
			     uint16_t reta_size);

int hinic_dev_xstats_get(struct rte_eth_dev *dev,
			 struct rte_eth_xstat *xstats, unsigned int n);
int hinic_dev_xstats_get_names(struct rte_eth_dev *dev,
			       struct rte_eth_xstat_name *xstats_names,
			       __rte_unused unsigned int limit);

int hinic_fw_version_get(struct rte_eth_dev *dev,
			char *fw_version, size_t fw_size);

#endif /* _HINIC_PMD_ETHDEV_H_ */