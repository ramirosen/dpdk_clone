/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <stdio.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ethdev_pci.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_dev.h>
#include <rte_errno.h>

#include "hinic_pmd_ethdev.h"
#include "hinic_pmd_tx.h"
#include "hinic_pmd_rx.h"

#define HINIC_MIN_RX_BUF_SIZE	1024

#define HINIC_MAX_MAC_ADDRS	1
#define EQ_MSIX_RESEND_TIMER_CLEAR	1


static int hinic_pf_dev_init(struct rte_eth_dev *eth_dev);
static int hinic_dev_uninit(struct rte_eth_dev *dev);
static int hinic_init_mac_addr(struct rte_eth_dev *eth_dev);
static void hinic_deinit_mac_addr(struct rte_eth_dev *eth_dev);
static int hinic_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			 uint16_t nb_desc, unsigned int socket_id,
			 __rte_unused const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp);
static int hinic_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			 uint16_t nb_desc, unsigned int socket_id,
			 __rte_unused const struct rte_eth_txconf *tx_conf);

static const struct eth_dev_ops hinic_pmd_ops = {
	.dev_configure                 = hinic_dev_configure,
	.dev_infos_get                 = hinic_dev_infos_get,
	.rx_queue_setup                = hinic_rx_queue_setup,
	.tx_queue_setup                = hinic_tx_queue_setup,
	.dev_start                     = hinic_dev_start,
	.link_update                   = hinic_link_update,
	.rx_queue_release              = hinic_rx_queue_release,
	.tx_queue_release              = hinic_tx_queue_release,
	.dev_stop                      = hinic_dev_stop,
	.dev_close                     = hinic_dev_close,
	.promiscuous_enable            = hinic_dev_promiscuous_enable,
	.promiscuous_disable           = hinic_dev_promiscuous_disable,
	.rss_hash_update               = hinic_rss_hash_update,
	.rss_hash_conf_get             = hinic_rss_conf_get,
	.reta_update                   = hinic_rss_indirtbl_update,
	.reta_query                    = hinic_rss_indirtbl_query,
	.stats_get                     = hinic_dev_stats_get,
	.stats_reset                   = hinic_dev_stats_reset,
	.xstats_get                    = hinic_dev_xstats_get,
	.xstats_reset                  = hinic_dev_xstats_reset,
	.xstats_get_names              = hinic_dev_xstats_get_names,
	.fw_version_get                = hinic_fw_version_get,
};

static struct rte_pci_id pci_id_hinic_pf_map[] = {
	{ RTE_PCI_DEVICE(HINIC_HUAWEI_VENDOR_ID, HINIC_DEV_ID_PRD) },
	{ RTE_PCI_DEVICE(HINIC_HUAWEI_VENDOR_ID, HINIC_DEV_ID_MEZZ_25GE) },
	{ RTE_PCI_DEVICE(HINIC_HUAWEI_VENDOR_ID, HINIC_DEV_ID_MEZZ_40GE) },
	{ RTE_PCI_DEVICE(HINIC_HUAWEI_VENDOR_ID, HINIC_DEV_ID_MEZZ_100GE) },
	{.vendor_id = 0},
};

static int hinic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(hinic_nic_dev), hinic_pf_dev_init);
}

static int hinic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, hinic_dev_uninit);
}

static struct rte_pci_driver rte_hinic_pmd = {
	.id_table = pci_id_hinic_pf_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = hinic_pci_probe,
	.remove = hinic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_hinic, rte_hinic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_hinic, pci_id_hinic_pf_map);

struct hinic_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	u32  offset;
};

#define HINIC_FUNC_STAT(_stat_item) {	\
	.name = #_stat_item, \
	.offset = offsetof(struct hinic_vport_stats, _stat_item) \
}

static const struct hinic_xstats_name_off hinic_vport_stats_strings[] = {
	HINIC_FUNC_STAT(tx_unicast_pkts_vport),
	HINIC_FUNC_STAT(tx_unicast_bytes_vport),
	HINIC_FUNC_STAT(tx_multicast_pkts_vport),
	HINIC_FUNC_STAT(tx_multicast_bytes_vport),
	HINIC_FUNC_STAT(tx_broadcast_pkts_vport),
	HINIC_FUNC_STAT(tx_broadcast_bytes_vport),

	HINIC_FUNC_STAT(rx_unicast_pkts_vport),
	HINIC_FUNC_STAT(rx_unicast_bytes_vport),
	HINIC_FUNC_STAT(rx_multicast_pkts_vport),
	HINIC_FUNC_STAT(rx_multicast_bytes_vport),
	HINIC_FUNC_STAT(rx_broadcast_pkts_vport),
	HINIC_FUNC_STAT(rx_broadcast_bytes_vport),

	HINIC_FUNC_STAT(tx_discard_vport),
	HINIC_FUNC_STAT(rx_discard_vport),
	HINIC_FUNC_STAT(tx_err_vport),
	HINIC_FUNC_STAT(rx_err_vport),
};

#define HINIC_VPORT_XSTATS_NUM (sizeof(hinic_vport_stats_strings) / \
		sizeof(hinic_vport_stats_strings[0]))

#define HINIC_PORT_STAT(_stat_item) { \
	.name = #_stat_item, \
	.offset = offsetof(struct hinic_phy_port_stats, _stat_item) \
}

static const struct hinic_xstats_name_off hinic_phyport_stats_strings[] = {
	HINIC_PORT_STAT(mac_rx_total_pkt_num),
	HINIC_PORT_STAT(mac_rx_total_oct_num),
	HINIC_PORT_STAT(mac_rx_bad_pkt_num),
	HINIC_PORT_STAT(mac_rx_bad_oct_num),
	HINIC_PORT_STAT(mac_rx_good_pkt_num),
	HINIC_PORT_STAT(mac_rx_good_oct_num),
	HINIC_PORT_STAT(mac_rx_uni_pkt_num),
	HINIC_PORT_STAT(mac_rx_multi_pkt_num),
	HINIC_PORT_STAT(mac_rx_broad_pkt_num),
	HINIC_PORT_STAT(mac_tx_total_pkt_num),
	HINIC_PORT_STAT(mac_tx_total_oct_num),
	HINIC_PORT_STAT(mac_tx_bad_pkt_num),
	HINIC_PORT_STAT(mac_tx_bad_oct_num),
	HINIC_PORT_STAT(mac_tx_good_pkt_num),
	HINIC_PORT_STAT(mac_tx_good_oct_num),
	HINIC_PORT_STAT(mac_tx_uni_pkt_num),
	HINIC_PORT_STAT(mac_tx_multi_pkt_num),
	HINIC_PORT_STAT(mac_tx_broad_pkt_num),
	HINIC_PORT_STAT(mac_rx_fragment_pkt_num),
	HINIC_PORT_STAT(mac_rx_undersize_pkt_num),
	HINIC_PORT_STAT(mac_rx_undermin_pkt_num),
	HINIC_PORT_STAT(mac_rx_64_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_65_127_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_128_255_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_256_511_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_512_1023_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_1024_1518_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_1519_2047_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_2048_4095_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_4096_8191_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_8192_9216_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_9217_12287_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_12288_16383_oct_pkt_num),
	HINIC_PORT_STAT(mac_rx_1519_max_bad_pkt_num),
	HINIC_PORT_STAT(mac_rx_1519_max_good_pkt_num),
	HINIC_PORT_STAT(mac_rx_oversize_pkt_num),
	HINIC_PORT_STAT(mac_rx_jabber_pkt_num),
	HINIC_PORT_STAT(mac_rx_mac_pause_num),
	HINIC_PORT_STAT(mac_rx_pfc_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri0_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri1_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri2_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri3_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri4_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri5_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri6_pkt_num),
	HINIC_PORT_STAT(mac_rx_pfc_pri7_pkt_num),
	HINIC_PORT_STAT(mac_rx_mac_control_pkt_num),
	HINIC_PORT_STAT(mac_rx_sym_err_pkt_num),
	HINIC_PORT_STAT(mac_rx_fcs_err_pkt_num),
	HINIC_PORT_STAT(mac_rx_send_app_good_pkt_num),
	HINIC_PORT_STAT(mac_rx_send_app_bad_pkt_num),
	HINIC_PORT_STAT(mac_tx_fragment_pkt_num),
	HINIC_PORT_STAT(mac_tx_undersize_pkt_num),
	HINIC_PORT_STAT(mac_tx_undermin_pkt_num),
	HINIC_PORT_STAT(mac_tx_64_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_65_127_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_128_255_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_256_511_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_512_1023_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_1024_1518_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_1519_2047_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_2048_4095_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_4096_8191_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_8192_9216_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_9217_12287_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_12288_16383_oct_pkt_num),
	HINIC_PORT_STAT(mac_tx_1519_max_bad_pkt_num),
	HINIC_PORT_STAT(mac_tx_1519_max_good_pkt_num),
	HINIC_PORT_STAT(mac_tx_oversize_pkt_num),
	HINIC_PORT_STAT(mac_trans_jabber_pkt_num),
	HINIC_PORT_STAT(mac_tx_mac_pause_num),
	HINIC_PORT_STAT(mac_tx_pfc_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri0_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri1_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri2_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri3_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri4_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri5_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri6_pkt_num),
	HINIC_PORT_STAT(mac_tx_pfc_pri7_pkt_num),
	HINIC_PORT_STAT(mac_tx_mac_control_pkt_num),
	HINIC_PORT_STAT(mac_tx_err_all_pkt_num),
	HINIC_PORT_STAT(mac_tx_from_app_good_pkt_num),
	HINIC_PORT_STAT(mac_tx_from_app_bad_pkt_num),
};

#define HINIC_PHYPORT_XSTATS_NUM (sizeof(hinic_phyport_stats_strings) / \
		sizeof(hinic_phyport_stats_strings[0]))

static const struct hinic_xstats_name_off hinic_rxq_stats_strings[] = {
	{"rx_nombuf", offsetof(struct hinic_rxq_stats, rx_nombuf)},

#ifdef HINIC_XSTAT_RXBUF_INFO
	{"rxmbuf", offsetof(struct hinic_rxq_stats, rx_mbuf)},
	{"avail", offsetof(struct hinic_rxq_stats, rx_avail)},
	{"hole", offsetof(struct hinic_rxq_stats, rx_hole)},
	{"burst_pkt", offsetof(struct hinic_rxq_stats, burst_pkts)},
#endif

#ifdef HINIC_XSTAT_PROF_RX
	{"app_tsc", offsetof(struct hinic_rxq_stats, app_tsc)},
	{"pmd_tsc", offsetof(struct hinic_rxq_stats, pmd_tsc)},
#endif

#ifdef HINIC_XSTAT_MBUF_USE
	{"rx_alloc_mbuf", offsetof(struct hinic_rxq_stats, alloc_mbuf)},
	{"rx_free_mbuf", offsetof(struct hinic_rxq_stats, free_mbuf)},
	{"rx_left_mbuf", offsetof(struct hinic_rxq_stats, left_mbuf)},
#endif
};

#define HINIC_RXQ_XSTATS_NUM (sizeof(hinic_rxq_stats_strings) / \
		sizeof(hinic_rxq_stats_strings[0]))

static const struct hinic_xstats_name_off hinic_txq_stats_strings[] = {
	{"tx_busy", offsetof(struct hinic_txq_stats, tx_busy)},
	{"offload_errors", offsetof(struct hinic_txq_stats, off_errs)},
	{"copy_pkts", offsetof(struct hinic_txq_stats, cpy_pkts)},
	{"rl_drop", offsetof(struct hinic_txq_stats, rl_drop)},

#ifdef HINIC_XSTAT_PROF_TX
	{"app_tsc", offsetof(struct hinic_txq_stats, app_tsc)},
	{"pmd_tsc", offsetof(struct hinic_txq_stats, pmd_tsc)},
	{"burst_pkts", offsetof(struct hinic_txq_stats, burst_pkts)},
#endif
};

#define HINIC_TXQ_XSTATS_NUM (sizeof(hinic_txq_stats_strings) / \
		sizeof(hinic_txq_stats_strings[0]))

static const struct rte_eth_desc_lim hinic_rx_desc_lim = {
	.nb_max = HINIC_MAX_QUEUE_DEPTH,
	.nb_min = HINIC_MIN_QUEUE_DEPTH,
	.nb_align = HINIC_RXD_ALIGN,
};

static const struct rte_eth_desc_lim hinic_tx_desc_lim = {
	.nb_max = HINIC_MAX_QUEUE_DEPTH,
	.nb_min = HINIC_MIN_QUEUE_DEPTH,
	.nb_align = HINIC_TXD_ALIGN,
};

static int hinic_xstats_calc_num(hinic_nic_dev *nic_dev)
{
	return (HINIC_VPORT_XSTATS_NUM +
		HINIC_PHYPORT_XSTATS_NUM +
		HINIC_RXQ_XSTATS_NUM * nic_dev->num_rq +
		HINIC_TXQ_XSTATS_NUM * nic_dev->num_sq);
}

static void hinic_dev_handle_aeq_event(hinic_nic_dev *nic_dev, void *param)
{
	struct hinic_hwdev *hwdev = nic_dev->hwdev;
	struct hinic_eq *aeq = &hwdev->aeqs->aeq[0];

	/* clear resend timer cnt register */
	hinic_misx_intr_clear_resend_bit(hwdev, aeq->eq_irq.msix_entry_idx,
					 EQ_MSIX_RESEND_TIMER_CLEAR);
	(void)hinic_aeq_poll_msg(aeq, 0, param);
}

/**
 * Interrupt handler triggered by NIC  for handling
 * specific event.
 *
 * @param: The address of parameter (struct rte_eth_dev *) regsitered before.
 **/
static void hinic_dev_interrupt_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	if (!hinic_test_bit(HINIC_DEV_INTR_EN, &nic_dev->dev_status)) {
		HINIC_LOG(INFO,
			  "Device's interrupt is disabled, ignore interrupt event, dev_name: %s, port_id: %d",
			  nic_dev->proc_dev_name, dev->data->port_id);
		return;
	}

	/* aeq0 msg handler */
	hinic_dev_handle_aeq_event(nic_dev, param);
}

static int hinic_dev_init(struct rte_eth_dev *eth_dev)
{
	int rc;
	struct rte_pci_device *pci_dev;
	struct ether_addr *eth_addr;
	hinic_nic_dev *nic_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* EAL is SECONDARY and eth_dev is already created */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		rc = rte_intr_callback_register(&pci_dev->intr_handle,
						hinic_dev_interrupt_handler,
						(void *)eth_dev);
		HINIC_PRINT("Initializing %s in secondary %s",
		    rc == HINIC_OK ? "successful" : "failed",
		    eth_dev->data->name);
		return rc;
	}

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);
	memset(nic_dev, 0, sizeof(*nic_dev));

	snprintf(nic_dev->proc_dev_name,
		 sizeof(nic_dev->proc_dev_name),
		 "hinic-%.4x:%.2x:%.2x.%x",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	/* clear RX ring mbuf allocated failed */
	eth_dev->data->rx_mbuf_alloc_failed = 0;

	/* alloc mac_addrs */
	eth_addr = (struct ether_addr *)rte_zmalloc("hinic_mac",
						    sizeof(*eth_addr), 0);
	HINIC_ERR_HANDLE(eth_addr == NULL, goto eth_addr_fail,
			 "Alloc hinic_mac failed, nic_dev:%s",
			 nic_dev->proc_dev_name);
	eth_dev->data->mac_addrs = eth_addr;

	/* create hardware nic_device */
	rc = hinic_nic_dev_create(eth_dev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto create_nic_dev_fail,
			 "Create nic device failed, nic_dev:%s",
			 nic_dev->proc_dev_name);

	rc = hinic_init_mac_addr(eth_dev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto init_mac_fail,
			 "Init mac vlan table failed, nic_dev:%s",
			 nic_dev->proc_dev_name);

	/* register callback func to eal lib */
	rc = rte_intr_callback_register(&pci_dev->intr_handle,
			hinic_dev_interrupt_handler, (void *)eth_dev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto reg_intr_cb_fail,
			 "Register rte_intr failed, nic_dev:%s",
			 nic_dev->proc_dev_name);

	/* enable uio/vfio intr/eventfd mapping */
	rc = rte_intr_enable(&pci_dev->intr_handle);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto enable_intr_fail,
			 "Enable rte_intr failed, nic_dev:%s",
			 nic_dev->proc_dev_name);

	hinic_set_bit(HINIC_DEV_INTR_EN, &nic_dev->dev_status);
	hinic_set_bit(HINIC_DEV_INIT, &nic_dev->dev_status);

	HINIC_PRINT("Initializing %s in primary successful",
		    nic_dev->proc_dev_name);

	return rc;

enable_intr_fail:
	(void)rte_intr_callback_unregister(&pci_dev->intr_handle,
					   hinic_dev_interrupt_handler,
					   (void *)eth_dev);

reg_intr_cb_fail:
	hinic_deinit_mac_addr(eth_dev);

init_mac_fail:
	hinic_nic_dev_destroy(eth_dev);

create_nic_dev_fail:
	rte_free(eth_addr);
	eth_dev->data->mac_addrs = NULL;

eth_addr_fail:
	rc = HINIC_ERROR;

	HINIC_PRINT("Initializing %s in primary failed",
		    nic_dev->proc_dev_name);
	return rc;
}

/**
 * PF Function device init.
 */
static int hinic_pf_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	HINIC_DEBUG("Initializing pf hinic-%.4x:%.2x:%.2x.%x in %s process",
		    pci_dev->addr.domain, pci_dev->addr.bus,
		    pci_dev->addr.devid, pci_dev->addr.function,
		    (rte_eal_process_type() == RTE_PROC_PRIMARY) ?
		    "primary" :"secondary");

	/* rte_eth_dev ops, rx_burst and tx_burst */
	eth_dev->dev_ops = &hinic_pmd_ops;
	eth_dev->rx_pkt_burst = hinic_recv_pkts;
	eth_dev->tx_pkt_burst = hinic_xmit_pkts;

	/* init hardware device */
	return hinic_dev_init(eth_dev);
}

/**
 * PF Function device uninit.
 */
static int hinic_dev_uninit(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	hinic_clear_bit(HINIC_DEV_INIT, &nic_dev->dev_status);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	hinic_dev_close(dev);

	dev->dev_ops = NULL;
	dev->rx_pkt_burst = NULL;
	dev->tx_pkt_burst = NULL;

	rte_free(dev->data->mac_addrs);
	dev->data->mac_addrs = NULL;

	return HINIC_OK;
}

/**
 * Ethernet device configuration.
 *
 * Prepare the driver for a given number of TX and RX queues, mtu size
 * and configure RSS.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
int hinic_dev_configure(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev;
	struct hinic_nic_io *nic_io;
	int err;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	nic_io = nic_dev->hwdev->nic_io;

	nic_dev->num_sq =  dev->data->nb_tx_queues;
	nic_dev->num_rq = dev->data->nb_rx_queues;

	nic_io->num_sqs =  dev->data->nb_tx_queues;
	nic_io->num_rqs = dev->data->nb_rx_queues;

	/* queue pair is max_num(sq, rq) */
	nic_dev->num_qps = (nic_dev->num_sq > nic_dev->num_rq) ?
			nic_dev->num_sq : nic_dev->num_rq;
	nic_io->num_qps = nic_dev->num_qps;

	if (nic_dev->num_qps > nic_io->max_qps) {
		dev_err(nic_dev->hwdev->dev_hdl,
			"Queue number out of range, get queue_num:%d, max_queue_num:%d\n",
			nic_dev->num_qps, nic_io->max_qps);
		return -EINVAL;
	}

	/* mtu size is 256~9600 */
	if (dev->data->dev_conf.rxmode.max_rx_pkt_len < HINIC_MIN_FRAME_SIZE ||
	    dev->data->dev_conf.rxmode.max_rx_pkt_len >
	    HINIC_MAX_JUMBO_FRAME_SIZE) {
		dev_err(nic_dev->hwdev->dev_hdl,
			"Max rx pkt len out of range, get max_rx_pkt_len:%d, "
			"expect between %d and %d\n",
			dev->data->dev_conf.rxmode.max_rx_pkt_len,
			HINIC_MIN_FRAME_SIZE, HINIC_MAX_JUMBO_FRAME_SIZE);
		return -EINVAL;
	}

	nic_dev->mtu_size =
		HINIC_PKTLEN_TO_MTU(dev->data->dev_conf.rxmode.max_rx_pkt_len);

	/* rss template */
	err = hinic_config_mq_mode(dev, TRUE);
	if (err) {
		dev_err(nic_dev->hwdev->dev_hdl, "Config multi-queue failed\n");
		return err;
	}

	HINIC_DEBUG("Configure %s successful, nb_tx_queues:%d, "
		    "nb_rx_queues:%d, nb_queue_pairs:%d",
		    dev->data->name, nic_dev->num_sq,
		    nic_dev->num_rq, nic_dev->num_qps);

	return HINIC_OK;
}

/**
 * DPDK callback to create the receive queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param queue_idx
 *   RX queue index.
 * @param nb_desc
 *   Number of descriptors for receive queue.
 * @param socket_id
 *   NUMA socket on which memory must be allocated.
 * @param rx_conf
 *   Thresholds parameters (unused_).
 * @param mp
 *   Memory pool for buffer allocations.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int hinic_rx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			 uint16_t nb_desc, unsigned int socket_id,
			 __rte_unused const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	int rc;
	hinic_nic_dev *nic_dev;
	struct hinic_rxq *rxq;
	u16 rq_depth, rx_free_thresh;
	u32 buf_size;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	/* queue depth must be power of 2, otherwise will be aligned up */
	rq_depth = (nb_desc & (nb_desc - 1)) ?
		((u16)(1U << (ilog2(nb_desc) + 1))) : nb_desc;

	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum and minmum.
	 */
	if ((rq_depth > HINIC_MAX_QUEUE_DEPTH) ||
		(rq_depth < HINIC_MIN_QUEUE_DEPTH)) {
		HINIC_LOG(ERR, "RX queue depth is out of range from %d to %d, (nb_desc=%d, q_depth=%d, port=%d queue=%d)",
			  HINIC_MIN_QUEUE_DEPTH, HINIC_MAX_QUEUE_DEPTH,
			  (int)nb_desc, (int)rq_depth,
			  (int)dev->data->port_id, (int)queue_idx);
		return -EINVAL;
	}

	/*
	 * The RX descriptor ring will be cleaned after rxq->rx_free_thresh
	 * descriptors are used or if the number of descriptors required
	 * to transmit a packet is greater than the number of free RX
	 * descriptors.
	 * The following constraints must be satisfied:
	 *  rx_free_thresh must be greater than 0.
	 *  rx_free_thresh must be less than the size of the ring minus 1.
	 * When set to zero use default values.
	 */
	rx_free_thresh = (u16)((rx_conf->rx_free_thresh) ?
			rx_conf->rx_free_thresh : HINIC_DEFAULT_RX_FREE_THRESH);
	if (rx_free_thresh >= (rq_depth - 1)) {
		HINIC_LOG(ERR, "rx_free_thresh must be less than the number of RX descriptors minus 1. (rx_free_thresh=%u port=%d queue=%d)",
			  (unsigned int)rx_free_thresh, (int)dev->data->port_id,
			  (int)queue_idx);
		return -EINVAL;
	}

	rxq = (struct hinic_rxq *)rte_zmalloc_socket("hinic_rx_queue",
						     sizeof(struct hinic_rxq),
						     RTE_CACHE_LINE_SIZE,
						     socket_id);
	HINIC_ERR_RET(nic_dev, rxq == NULL, -ENOMEM,
		      "Alloc rxq[%d] failed", queue_idx);
	nic_dev->rxqs[queue_idx] = rxq;

	/* alloc rx sq hw wqepage*/
	rc = hinic_create_rq(nic_dev, queue_idx, rq_depth);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto ceate_rq_fail,
			 "Create rxq[%d] failed, eth_dev: %s, rq_depth: %d",
			 queue_idx, dev->data->name, rq_depth);

	/* mbuf pool must be assigned before setup rx resources */
	rxq->mb_pool = mp;

	rc = hinic_convert_rx_buf_size(rte_pktmbuf_data_room_size(rxq->mb_pool) -
				       RTE_PKTMBUF_HEADROOM, &buf_size);
	HINIC_ERR_HANDLE(rc != 0, goto adjust_bufsize_fail,
			 "Adjust buf size fail, eth_dev:%s", dev->data->name);

	/* rx queue info, rearm control */
	rxq->wq = &nic_dev->nic_io->rq_wq[queue_idx];
	rxq->pi_virt_addr = nic_dev->nic_io->qps[queue_idx].rq.pi_virt_addr;
	rxq->nic_dev = nic_dev;
	rxq->q_id = queue_idx;
	rxq->q_depth = rq_depth;
	rxq->buf_len = (u16)buf_size;
	rxq->rx_free_thresh = rx_free_thresh;

	/* the last point cant do mbuf rearm in bulk */
	rxq->rxinfo_align_end = rxq->q_depth - rxq->rx_free_thresh;

	/* device port identifier */
	rxq->port_id = dev->data->port_id;

	/* alloc rx_cqe and prepare rq_wqe */
	rc = hinic_setup_rx_resources(rxq);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto setup_rx_res_err,
			 "Setup rxq[%d] rx_resources failed, eth_dev:%s, error:%d",
			 queue_idx, dev->data->name, rc);

	/* record nic_dev rxq in rte_eth rx_queues */
	dev->data->rx_queues[queue_idx] = rxq;

	HINIC_DEBUG("Setup rxq[%d] successful, eth_dev:%s, nb_desc:%d, rq_depth:%d",
		    queue_idx, dev->data->name, nb_desc, rq_depth);

	return HINIC_OK;

setup_rx_res_err:
adjust_bufsize_fail:
	hinic_destroy_rq(nic_dev, queue_idx);

ceate_rq_fail:
	rte_free(rxq);

	return rc;
}

static void hinic_reset_rx_queue(struct rte_eth_dev *dev)
{
	struct hinic_rxq *rxq;
	hinic_nic_dev *nic_dev;
	int q_id = 0;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	for (q_id = 0; q_id < nic_dev->num_rq; q_id++) {
		rxq = (struct hinic_rxq *)dev->data->rx_queues[q_id];

		rxq->wq->cons_idx = 0;
		rxq->wq->prod_idx = 0;
		rxq->wq->delta = rxq->q_depth;
		rxq->wq->mask = rxq->q_depth - 1;

		/* alloc mbuf to rq */
		hinic_rx_alloc_pkts(rxq);
	}
}

/**
 * DPDK callback to configure the transmit queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param queue_idx
 *   Transmit queue index.
 * @param nb_desc
 *   Number of descriptors for transmit queue.
 * @param socket_id
 *   NUMA socket on which memory must be allocated.
 * @param tx_conf
 *   Tx queue configuration parameters.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int hinic_tx_queue_setup(struct rte_eth_dev *dev, uint16_t queue_idx,
			 uint16_t nb_desc, unsigned int socket_id,
			 __rte_unused const struct rte_eth_txconf *tx_conf)
{
	int rc;
	hinic_nic_dev *nic_dev;
	struct hinic_txq *txq;
	u16 sq_depth, tx_free_thresh;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	/* queue depth must be power of 2, otherwise will be aligned up */
	sq_depth = (nb_desc & (nb_desc - 1)) ?
			((u16)(1U << (ilog2(nb_desc) + 1))) : nb_desc;

	/*
	 * Validate number of transmit descriptors.
	 * It must not exceed hardware maximum and minmum.
	 */
	if ((sq_depth > HINIC_MAX_QUEUE_DEPTH) ||
		(sq_depth < HINIC_MIN_QUEUE_DEPTH)) {
		HINIC_LOG(ERR, "TX queue depth is out of range from %d to %d, (nb_desc=%d, q_depth=%d, port=%d queue=%d)",
			  HINIC_MIN_QUEUE_DEPTH, HINIC_MAX_QUEUE_DEPTH,
			  (int)nb_desc, (int)sq_depth,
			  (int)dev->data->port_id, (int)queue_idx);
		return -EINVAL;
	}

	/*
	 * The TX descriptor ring will be cleaned after txq->tx_free_thresh
	 * descriptors are used or if the number of descriptors required
	 * to transmit a packet is greater than the number of free TX
	 * descriptors.
	 * The following constraints must be satisfied:
	 *  tx_free_thresh must be greater than 0.
	 *  tx_free_thresh must be less than the size of the ring minus 1.
	 * When set to zero use default values.
	 */
	tx_free_thresh = (u16)((tx_conf->tx_free_thresh) ?
			tx_conf->tx_free_thresh : HINIC_DEFAULT_TX_FREE_THRESH);
	if (tx_free_thresh >= (sq_depth - 1)) {
		HINIC_LOG(ERR, "tx_free_thresh must be less than the number of TX descriptors minus 1. (tx_free_thresh=%u port=%d queue=%d)",
			(unsigned int)tx_free_thresh, (int)dev->data->port_id,
			(int)queue_idx);
		return -EINVAL;
	}

	txq = (struct hinic_txq *)rte_zmalloc_socket("hinic_tx_queue",
		sizeof(struct hinic_txq), RTE_CACHE_LINE_SIZE, socket_id);
	HINIC_ERR_RET(nic_dev, NULL == txq, -ENOMEM, "Alloc txq[%d] failed",
		      queue_idx);
	nic_dev->txqs[queue_idx] = txq;

	/* alloc tx sq hw wqepage */
	rc = hinic_create_sq(nic_dev, queue_idx, sq_depth);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto create_sq_fail,
			 "Create txq[%d] failed, eth_dev:%s, sq_depth:%d",
			 queue_idx, dev->data->name, sq_depth);

	txq->q_id = queue_idx;
	txq->q_depth = sq_depth;
	txq->port_id = dev->data->port_id;
	txq->tx_free_thresh = tx_free_thresh;
	txq->nic_dev = nic_dev;
	txq->wq = &nic_dev->nic_io->sq_wq[queue_idx];
	txq->sq = &nic_dev->nic_io->qps[queue_idx].sq;
	txq->cons_idx_addr = nic_dev->nic_io->qps[queue_idx].sq.cons_idx_addr;
	txq->sq_head_addr = HINIC_GET_WQ_HEAD(txq);
	txq->sq_bot_sge_addr = HINIC_GET_WQ_TAIL(txq) -
				sizeof(struct hinic_sq_bufdesc);
	txq->cos = nic_dev->default_cos;

	/* alloc software txinfo */
	rc = hinic_setup_tx_resources(txq);
	HINIC_ERR_HANDLE(HINIC_OK != rc, goto setup_tx_res_fail,
			 "Setup txq[%d] tx_resources failed, eth_dev:%s, error:%d",
			 queue_idx, dev->data->name, rc);

	/* record nic_dev txq in rte_eth tx_queues */
	dev->data->tx_queues[queue_idx] = txq;

	HINIC_DEBUG("Setup txq[%d] successful, eth_dev:%s, nb_desc:%d, sq_depth:%d",
		    queue_idx, dev->data->name, nb_desc, sq_depth);

	return HINIC_OK;

setup_tx_res_fail:
	hinic_destroy_sq(nic_dev, queue_idx);

create_sq_fail:
	rte_free(txq);

	return rc;
}

static void hinic_reset_tx_queue(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev;
	struct hinic_txq *txq;
	struct hinic_nic_io *nic_io;
	struct hinic_hwdev *hwdev;
	volatile u32 *ci_addr;
	int q_id = 0;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	hwdev = nic_dev->hwdev;
	nic_io = hwdev->nic_io;

	for (q_id = 0; q_id < nic_dev->num_sq; q_id++) {
		txq = (struct hinic_txq *)dev->data->tx_queues[q_id];

		txq->wq->cons_idx = 0;
		txq->wq->prod_idx = 0;
		txq->wq->delta = txq->q_depth;
		txq->wq->mask  = txq->q_depth - 1;

		/*clear hardware ci*/
		ci_addr = (volatile u32 *)HINIC_CI_VADDR(nic_io->ci_vaddr_base,
							q_id);
		*ci_addr = 0;
	}
}

/**
 * Get link speed from NIC.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param speed_capa
 *   Pointer to link speed structure.
 */
static void hinic_get_speed_capa(struct rte_eth_dev *dev, uint32_t *speed_capa)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	u32 supported_link, advertised_link;
	int err;

#define HINIC_LINK_MODE_SUPPORT_1G	(1U << HINIC_GE_BASE_KX)

#define HINIC_LINK_MODE_SUPPORT_10G	(1U << HINIC_10GE_BASE_KR)

#define HINIC_LINK_MODE_SUPPORT_25G	((1U << HINIC_25GE_BASE_KR_S) | \
					(1U << HINIC_25GE_BASE_CR_S) | \
					(1U << HINIC_25GE_BASE_KR) | \
					(1U << HINIC_25GE_BASE_CR))

#define HINIC_LINK_MODE_SUPPORT_40G	((1U << HINIC_40GE_BASE_KR4) | \
					(1U << HINIC_40GE_BASE_CR4))

#define HINIC_LINK_MODE_SUPPORT_100G	((1U << HINIC_100GE_BASE_KR4) | \
					(1U << HINIC_100GE_BASE_CR4))

	err = hinic_get_link_mode(nic_dev->hwdev,
				  &supported_link, &advertised_link);
	if (err || supported_link == HINIC_SUPPORTED_UNKNOWN ||
	    advertised_link == HINIC_SUPPORTED_UNKNOWN) {
		HINIC_LOG(WARNING, "Get speed capability info failed, device: %s, port_id: %u",
			  nic_dev->proc_dev_name, dev->data->port_id);
	} else {
		*speed_capa = 0;
		if (!!(supported_link & HINIC_LINK_MODE_SUPPORT_1G))
			*speed_capa |= ETH_LINK_SPEED_1G;
		if (!!(supported_link & HINIC_LINK_MODE_SUPPORT_10G))
			*speed_capa |= ETH_LINK_SPEED_10G;
		if (!!(supported_link & HINIC_LINK_MODE_SUPPORT_25G))
			*speed_capa |= ETH_LINK_SPEED_25G;
		if (!!(supported_link & HINIC_LINK_MODE_SUPPORT_40G))
			*speed_capa |= ETH_LINK_SPEED_40G;
		if (!!(supported_link & HINIC_LINK_MODE_SUPPORT_100G))
			*speed_capa |= ETH_LINK_SPEED_100G;
	}
}

/**
 * DPDK callback to get information about the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param info
 *   Pointer to Info structure output buffer.
 */
void hinic_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *info)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	info->max_rx_queues  = nic_dev->nic_cap.max_rqs;
	info->max_tx_queues  = nic_dev->nic_cap.max_sqs;
	info->min_rx_bufsize = HINIC_MIN_RX_BUF_SIZE;
	info->max_rx_pktlen  = HINIC_MAX_JUMBO_FRAME_SIZE;
	info->max_mac_addrs  = HINIC_MAX_MAC_ADDRS;

	hinic_get_speed_capa(dev, &info->speed_capa);
	info->rx_queue_offload_capa = 0;
	info->rx_offload_capa = DEV_RX_OFFLOAD_VLAN_STRIP |
				DEV_RX_OFFLOAD_IPV4_CKSUM |
				DEV_RX_OFFLOAD_UDP_CKSUM |
				DEV_RX_OFFLOAD_TCP_CKSUM |
				DEV_RX_OFFLOAD_VLAN_FILTER |
				DEV_RX_OFFLOAD_JUMBO_FRAME;

	info->tx_queue_offload_capa = 0;
	info->tx_offload_capa = DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM |
				DEV_TX_OFFLOAD_UDP_CKSUM |
				DEV_TX_OFFLOAD_TCP_CKSUM |
				DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
				DEV_TX_OFFLOAD_TCP_TSO;

	info->hash_key_size = HINIC_RSS_KEY_SIZE;
	info->reta_size = HINIC_RSS_INDIR_SIZE;
	info->flow_type_rss_offloads = HINIC_RSS_OFFLOAD_ALL;
	info->rx_desc_lim = hinic_rx_desc_lim;
	info->tx_desc_lim = hinic_tx_desc_lim;
}

int hinic_rxtx_configure(struct rte_eth_dev *dev)
{
	int err;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	/* rx configure, if rss enable, need to init default configuration */
	err = hinic_rx_configure(dev);
	if (err) {
		dev_err(NULL, "Configure rss failed\n");
		return err;
	}

	/* rx mode init */
	err = hinic_config_rx_mode(nic_dev, HINIC_DEFAULT_RX_MODE);
	if (err) {
		dev_err(NULL, "Configure rx_mode:0x%x failed\n",
			HINIC_DEFAULT_RX_MODE);
		goto set_rx_mode_fail;
	}

	return HINIC_OK;

set_rx_mode_fail:
	hinic_rx_remove_configure(dev);

	return err;
}

static void hinic_remove_rxtx_configure(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	(void)hinic_config_rx_mode(nic_dev, 0);
	hinic_rx_remove_configure(dev);
}

/**
 * DPDK callback to start the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
int hinic_dev_start(struct rte_eth_dev *dev)
{
	int rc;
	char *name;
	hinic_nic_dev *nic_dev;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	name = dev->data->name;

	/* reset rx and tx queue */
	hinic_reset_rx_queue(dev);
	hinic_reset_tx_queue(dev);

	/* init txq and rxq context */
	rc = hinic_init_qp_ctxts(nic_dev->hwdev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto init_qp_fail,
			 "Init qp context fail, eth_dev:%s", name);

	/* rss template */
	rc = hinic_config_mq_mode(dev, TRUE);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto cfg_mq_mode_fail,
			"Init qp context fail, eth_dev:%s", name);

	/* set default mtu */
	rc = hinic_set_port_mtu(nic_dev->hwdev, nic_dev->mtu_size);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto set_mtu_fail,
			 "Set mtu_size:%d failed, eth_dev:%s, error:%d",
			 nic_dev->mtu_size, name, rc);

	/* configure rss rx_mode and other rx or tx default feature */
	rc = hinic_rxtx_configure(dev);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto cfg_rxtx_fail,
			 "Config tx and rx failed, eth_dev:%s, error:%d",
			 name, rc);
	/* open virtual port and ready to start packet receiving */
	rc = hinic_set_vport_enable(nic_dev->hwdev, true);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto en_vport_fail,
			"Enable vport failed, dev_name:%s, port_id:%d",
			  nic_dev->proc_dev_name, dev->data->port_id);

	/* open pyhsical port and start packet receiving */
	rc = hinic_set_port_enable(nic_dev->hwdev, true);
	HINIC_ERR_HANDLE(rc != HINIC_OK, goto en_port_fail,
			"Enable phy port failed, dev_name:%s, port_id:%d",
			  nic_dev->proc_dev_name, dev->data->port_id);

	/* update eth_dev link status */
	if (dev->data->dev_conf.intr_conf.lsc != 0)
		(void)hinic_link_update(dev, 0);

	hinic_set_bit(HINIC_DEV_START, &nic_dev->dev_status);

	HINIC_LOG(INFO, "Device %s started", name);

	return rc;

en_port_fail:
	(void)hinic_set_vport_enable(nic_dev->hwdev, false);

en_vport_fail:
	/* Flush tx && rx chip resources in case of set vport fake fail */
	(void)hinic_flush_qp_res(nic_dev->hwdev);
	msleep(100);

	hinic_remove_rxtx_configure(dev);

cfg_rxtx_fail:
set_mtu_fail:
cfg_mq_mode_fail:
	hinic_free_qp_ctxts(nic_dev->hwdev);

init_qp_fail:
	hinic_free_all_rx_mbuf(dev);
	hinic_free_all_tx_mbuf(dev);

	return rc;
}

/**
 * DPDK callback to release the receive queue.
 *
 * @param queue
 *   Generic receive queue pointer.
 */
void hinic_rx_queue_release(void *queue)
{
	struct hinic_rxq *rxq = (struct hinic_rxq *)queue;
	hinic_nic_dev *nic_dev;

	if (!rxq) {
		HINIC_PRINT_WARN("Release a NULL rxq");
		return;
	}

	nic_dev = (hinic_nic_dev *)rxq->nic_dev;

	/* free rxq_pkt mbuf */
	hinic_free_all_rx_skbs(rxq);

	/* free rxq_cqe, rxq_info */
	hinic_free_rx_resources(rxq);

	/* free root rq wq */
	hinic_destroy_rq(nic_dev, rxq->q_id);

	nic_dev->rxqs[rxq->q_id] = NULL;

	HINIC_DEBUG("Release rxq[%d], eth_dev:%s, q_depth:%d",
		    rxq->q_id, nic_dev->proc_dev_name, rxq->q_depth);

	/* free rxq */
	rte_free(rxq);
}

/**
 * DPDK callback to release the transmit queue.
 *
 * @param queue
 *   Generic transmit queue pointer.
 */
void hinic_tx_queue_release(void *queue)
{
	struct hinic_txq *txq = (struct hinic_txq *)queue;
	hinic_nic_dev *nic_dev;

	if (!txq) {
		HINIC_PRINT_WARN("Txq is null when release");
		return;
	}
	nic_dev = (hinic_nic_dev *)txq->nic_dev;

	/* free txq_pkt mbuf */
	hinic_free_all_tx_skbs(txq);

	/* free txq_info */
	hinic_free_tx_resources(txq);

	/* free root sq wq */
	hinic_destroy_sq(nic_dev, txq->q_id);
	nic_dev->txqs[txq->q_id] = NULL;

	HINIC_DEBUG("Release txq[%d], eth_dev:%s, q_depth:%d",
		    txq->q_id, nic_dev->proc_dev_name, txq->q_depth);

	/* free txq */
	rte_free(txq);
}

/**
 * Atomically writes the link status information into global
 * struct rte_eth_dev.
 */
int hinic_dev_atomic_write_link_status(struct rte_eth_dev *dev,
				       struct rte_eth_link *link)
{
	struct rte_eth_link *dst = &dev->data->dev_link;
	struct rte_eth_link *src = link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
	    *(uint64_t *)src) == 0)
		return HINIC_ERROR;

	return HINIC_OK;
}

/**
 * Atomically reads the link status information from global
 * structure rte_eth_dev.
 */
int hinic_dev_atomic_read_link_status(struct rte_eth_dev *dev,
				      struct rte_eth_link *link)
{
	struct rte_eth_link *dst = link;
	struct rte_eth_link *src = &dev->data->dev_link;

	if (rte_atomic64_cmpset((uint64_t *)dst, *(uint64_t *)dst,
	    *(uint64_t *)src) == 0)
		return HINIC_ERROR;

	return HINIC_OK;
}

void hinic_free_all_rq(hinic_nic_dev *nic_dev)
{
	u16 q_id;

	for (q_id = 0; q_id < nic_dev->num_rq; q_id++)
		hinic_destroy_rq(nic_dev, q_id);
}

void hinic_free_all_sq(hinic_nic_dev *nic_dev)
{
	u16 q_id;

	for (q_id = 0; q_id < nic_dev->num_sq; q_id++)
		hinic_destroy_sq(nic_dev, q_id);
}

/**
 * DPDK callback to stop the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void hinic_dev_stop(struct rte_eth_dev *dev)
{
	int rc;
	char *name;
	uint16_t port_id;
	hinic_nic_dev *nic_dev ;
	struct rte_eth_link link;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	name = dev->data->name;
	port_id = dev->data->port_id;

	if (!hinic_test_and_clear_bit(HINIC_DEV_START, &nic_dev->dev_status)) {
		HINIC_LOG(INFO, "Device %s already stopped", name);
		return;
	}

	/* just stop phy port and vport */
	rc = hinic_set_port_enable(nic_dev->hwdev, false);
	if (rc)
		HINIC_LOG(WARNING, "Disable phy port failed, error: %d, dev_name:%s, port_id:%d",
			  rc, name, port_id);

	rc = hinic_set_vport_enable(nic_dev->hwdev, false);
	if (rc)
		HINIC_LOG(WARNING, "Disable vport failed, error: %d, dev_name:%s, port_id:%d",
			  rc, name, port_id);

	/* Clear recorded link status */
	memset(&link, 0, sizeof(link));
	(void)hinic_dev_atomic_write_link_status(dev, &link);

	/* flush pending io request */
	rc = hinic_rx_tx_flush(nic_dev->hwdev);
	if (rc)
		HINIC_LOG(WARNING,
		"Flush pending io failed, error: %d, dev_name: %s, port_id: %d\n",
		rc, name, port_id);

	/* clean rss table and rx_mode */
	hinic_remove_rxtx_configure(dev);

	/* clean root context */
	hinic_free_qp_ctxts(nic_dev->hwdev);

	/* free mbuf */
	hinic_free_all_rx_mbuf(dev);
	hinic_free_all_tx_mbuf(dev);

	HINIC_LOG(INFO, "Device %s stopped", name);
}

void hinic_disable_interrupt(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	int ret, retries = 0;

	hinic_clear_bit(HINIC_DEV_INTR_EN, &nic_dev->dev_status);

	/* disable msix interrupt in hardware */
	hinic_set_msix_state(nic_dev->hwdev, 0, HINIC_MSIX_DISABLE);

	/* disable rte interrupt */
	ret = rte_intr_disable(&pci_dev->intr_handle);
	if (ret)
		HINIC_LOG(ERR, "Disable intr failed: %d", ret);

	do {
		ret =
		rte_intr_callback_unregister(&pci_dev->intr_handle,
					     hinic_dev_interrupt_handler, dev);
		if (ret == -EAGAIN) {
			rte_delay_ms(100);
			retries++;
		} else if (ret >= 0) {
			break;
		} else {
			HINIC_LOG(ERR, "intr callback unregister failed: %d",
				  ret);
			break;
		}
	} while (retries < HINIC_INTR_CB_UNREG_MAX_RETRIES);

	if (retries == HINIC_INTR_CB_UNREG_MAX_RETRIES)
		HINIC_LOG(ERR, "Unregister intr callback failed after %d retries",
			  retries);
}

/**
 * DPDK callback to close the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void hinic_dev_close(struct rte_eth_dev *dev)
{
	char *name;
	hinic_nic_dev *nic_dev;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	name = dev->data->name;

	if (hinic_test_and_set_bit(HINIC_DEV_CLOSE, &nic_dev->dev_status)) {
		HINIC_LOG(INFO, "Device %s already closed", name);
		return;
	}

	/* stop device first */
	hinic_dev_stop(dev);

	/* rx_cqe, rx_info */
	hinic_free_all_rx_resources(dev);

	/* tx_info */
	hinic_free_all_tx_resources(dev);

	/* free wq, pi_dma_addr */
	hinic_free_all_rq(nic_dev);

	/* free wq, db_addr */
	hinic_free_all_sq(nic_dev);

	/* deinit mac vlan tbl */
	hinic_deinit_mac_addr(dev);

	/* disable hardware and uio interrupt */
	hinic_disable_interrupt(dev);

	/* deinit nic hardware device */
	hinic_nic_dev_destroy(dev);

	HINIC_LOG(INFO, "Device %s closed", name);
}

static int hinic_priv_get_dev_link_status(hinic_nic_dev *nic_dev,
					  struct rte_eth_link *link)
{
	int rc = HINIC_OK;
	u8 port_link_status = 0;
	struct nic_port_info port_link_info;
	struct hinic_hwdev *nic_hwdev = nic_dev->hwdev;
	uint32_t port_speed[LINK_SPEED_MAX] = {ETH_SPEED_NUM_10M,
					ETH_SPEED_NUM_100M, ETH_SPEED_NUM_1G,
					ETH_SPEED_NUM_10G, ETH_SPEED_NUM_25G,
					ETH_SPEED_NUM_40G, ETH_SPEED_NUM_100G};

	memset(link, 0, sizeof(*link));
	rc = hinic_get_link_status(nic_hwdev, &port_link_status);
	HINIC_ERR_RET(nic_dev, HINIC_OK != rc, rc, "Get link status failed");

	nic_dev->link_status = port_link_status;
	if (!port_link_status) {
		link->link_status = ETH_LINK_DOWN;
		link->link_speed = 0;
		link->link_duplex = ETH_LINK_HALF_DUPLEX;
		link->link_autoneg = ETH_LINK_FIXED;
		return rc;
	}

	memset(&port_link_info, 0, sizeof(port_link_info));
	rc = hinic_get_port_info(nic_hwdev, &port_link_info);
	HINIC_ERR_RET(nic_dev, rc != HINIC_OK, rc,
		      "Get hinic port info failed");

	link->link_speed = port_speed[port_link_info.speed % LINK_SPEED_MAX];
	link->link_duplex = port_link_info.duplex;
	link->link_autoneg = port_link_info.autoneg_state;
	link->link_status = port_link_status;

	return rc;
}

static int hinic_priv_set_dev_promiscuous(hinic_nic_dev *nic_dev, bool enable)
{
	u32 rx_mode_ctrl = nic_dev->rx_mode_status;

	if (enable)
		rx_mode_ctrl |= HINIC_RX_MODE_PROMISC;
	else
		rx_mode_ctrl &= (~HINIC_RX_MODE_PROMISC);

	return hinic_config_rx_mode(nic_dev, rx_mode_ctrl);
}

/**
 * DPDK callback to get device statistics.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param stats
 *   Stats structure output buffer.
 *
 * @return
 *   0 on success and stats is filled,
 *   negative error value otherwise.
 */
int hinic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	int i, err, q_num;
	u64 rx_discards_pmd = 0;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	struct hinic_vport_stats vport_stats;
	struct hinic_rxq	*rxq = NULL;
	struct hinic_rxq_stats rxq_stats;
	struct hinic_txq	*txq = NULL;
	struct hinic_txq_stats txq_stats;

	err = hinic_get_vport_stats(nic_dev->hwdev, &vport_stats);
	if (err) {
		dev_err(nic_dev, "Get vport stats from fw failed, nic_dev: %s\n",
			nic_dev->proc_dev_name);
		return err;
	}

	dev->data->rx_mbuf_alloc_failed = 0;

	/* rx queue stats */
	q_num = (nic_dev->num_rq < RTE_ETHDEV_QUEUE_STAT_CNTRS) ?
			nic_dev->num_rq : RTE_ETHDEV_QUEUE_STAT_CNTRS;
	for (i = 0; i < q_num; i++) {
		rxq = nic_dev->rxqs[i];
		hinic_rxq_get_stats(rxq, &rxq_stats);
		stats->q_ipackets[i] = rxq_stats.packets;
		stats->q_ibytes[i] = rxq_stats.bytes;
		stats->q_errors[i] = rxq_stats.rx_discards;

		stats->ierrors += rxq_stats.errors;
		rx_discards_pmd += rxq_stats.rx_discards;
		dev->data->rx_mbuf_alloc_failed += rxq_stats.rx_nombuf;
	}

	/* tx queue stats */
	q_num = (nic_dev->num_sq < RTE_ETHDEV_QUEUE_STAT_CNTRS) ?
		nic_dev->num_sq : RTE_ETHDEV_QUEUE_STAT_CNTRS;
	for (i = 0; i < q_num; i++) {
		txq = nic_dev->txqs[i];
		hinic_txq_get_stats(txq, &txq_stats);
		stats->q_opackets[i] = txq_stats.packets;
		stats->q_obytes[i] = txq_stats.bytes;
		stats->oerrors += (txq_stats.tx_busy + txq_stats.off_errs);
	}

	/* vport stats */
	stats->oerrors += vport_stats.tx_discard_vport;

	stats->imissed = vport_stats.rx_discard_vport + rx_discards_pmd;

	stats->ipackets = (vport_stats.rx_unicast_pkts_vport +
			vport_stats.rx_multicast_pkts_vport +
			vport_stats.rx_broadcast_pkts_vport -
			rx_discards_pmd);

	stats->opackets = (vport_stats.tx_unicast_pkts_vport +
			vport_stats.tx_multicast_pkts_vport +
			vport_stats.tx_broadcast_pkts_vport);

	stats->ibytes = (vport_stats.rx_unicast_bytes_vport +
			vport_stats.rx_multicast_bytes_vport +
			vport_stats.rx_broadcast_bytes_vport);

	stats->obytes = (vport_stats.tx_unicast_bytes_vport +
			vport_stats.tx_multicast_bytes_vport +
			vport_stats.tx_broadcast_bytes_vport);
	return 0;
}

/**
 * DPDK callback to clear device statistics.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void hinic_dev_stats_reset(struct rte_eth_dev *dev)
{
	int qid;
	struct hinic_rxq	*rxq = NULL;
	struct hinic_txq	*txq = NULL;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	hinic_clear_vport_stats(nic_dev->hwdev);

	for (qid = 0; qid < nic_dev->num_rq; qid++) {
		rxq = nic_dev->rxqs[qid];
		hinic_rxq_stats_reset(rxq);
	}

	for (qid = 0; qid < nic_dev->num_sq; qid++) {
		txq = nic_dev->txqs[qid];
		hinic_txq_stats_reset(txq);
	}
}

/**
 * DPDK callback to clear device extended statistics.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 **/
void hinic_dev_xstats_reset(struct rte_eth_dev *dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	hinic_dev_stats_reset(dev);

	if (hinic_func_type(nic_dev->hwdev) != TYPE_VF)
		hinic_clear_phy_port_stats(nic_dev->hwdev);
}

static void hinic_gen_random_mac_addr(struct ether_addr *mac_addr)
{
	uint64_t random_value;

	/* Set Organizationally Unique Identifier (OUI) prefix */
	mac_addr->addr_bytes[0] = 0x00;
	mac_addr->addr_bytes[1] = 0x09;
	mac_addr->addr_bytes[2] = 0xC0;
	/* Force indication of locally assigned MAC address. */
	mac_addr->addr_bytes[0] |= ETHER_LOCAL_ADMIN_ADDR;
	/* Generate the last 3 bytes of the MAC address with a random number. */
	random_value = rte_rand();
	memcpy(&mac_addr->addr_bytes[3], &random_value, 3);
}

/**
 * Init mac_vlan table in NIC.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success and stats is filled,
 *   negative error value otherwise.
 */
static int hinic_init_mac_addr(struct rte_eth_dev *eth_dev)
{
	int rc = 0;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);
	uint8_t addr_bytes[ETHER_ADDR_LEN];
	u16 func_id = 0;

	rc = hinic_get_default_mac(nic_dev->hwdev, addr_bytes);
	if (rc == HINIC_OK) {
		ether_addr_copy((struct ether_addr *)addr_bytes,
				eth_dev->data->mac_addrs);
	} else {
		HINIC_ERR_RET(nic_dev, rc != HINIC_OK, rc,
			"%s get default mac fail", nic_dev->proc_dev_name);
	}

	if (is_zero_ether_addr(eth_dev->data->mac_addrs))
		hinic_gen_random_mac_addr(eth_dev->data->mac_addrs);

	func_id = hinic_global_func_id(nic_dev->hwdev);
	rc = hinic_set_mac(nic_dev->hwdev, eth_dev->data->mac_addrs->addr_bytes,
			0, func_id);
	HINIC_ERR_RET(nic_dev, (rc && rc != HINIC_PF_SET_VF_ALREADY), rc,
		      "%s set mac vlan table failed", nic_dev->proc_dev_name);

	return 0;
}

/**
 * Deinit mac_vlan table in NIC.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success and stats is filled,
 *   negative error value otherwise.
 */
static void hinic_deinit_mac_addr(struct rte_eth_dev *eth_dev)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(eth_dev);
	int rc;
	u16 func_id = 0;

	if (is_zero_ether_addr(eth_dev->data->mac_addrs))
		return;

	func_id = hinic_global_func_id(nic_dev->hwdev);
	rc = hinic_del_mac(nic_dev->hwdev,
			   eth_dev->data->mac_addrs->addr_bytes,
			   0, func_id);
	HINIC_ERR_HANDLE((rc && rc != HINIC_PF_SET_VF_ALREADY), return,
			 "%s del mac vlan table failed", nic_dev->proc_dev_name);
}

/**
 * DPDK callback to retrieve physical link information.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param wait_to_complete
 *   Wait for request completion.
 *
 * @return
 *   0 link status changed, -1 link status not changed
 */
int hinic_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
#define CHECK_INTERVAL 10  /* 10ms */
#define MAX_REPEAT_TIME 100  /* 1s (100 * 10ms) in total */
	int rc = HINIC_OK;
	struct rte_eth_link new_link, old_link;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	unsigned int rep_cnt = MAX_REPEAT_TIME;

	memset(&old_link, 0, sizeof(old_link));
	memset(&new_link, 0, sizeof(new_link));
	(void)hinic_dev_atomic_read_link_status(dev, &old_link);

	do {
		/* Get link status information from hardware */
		rc = hinic_priv_get_dev_link_status(nic_dev, &new_link);
		if (rc != HINIC_OK) {
			new_link.link_speed = ETH_SPEED_NUM_NONE;
			new_link.link_duplex = ETH_LINK_FULL_DUPLEX;
			HINIC_PRINT_ERR("Get link status failed");
			goto out;
		}

		if (!wait_to_complete)
			break;

		rte_delay_ms(CHECK_INTERVAL);
	} while (!new_link.link_status && rep_cnt--);

out:
	(void)hinic_dev_atomic_write_link_status(dev, &new_link);

	if (old_link.link_status == new_link.link_status)
		return HINIC_ERROR;

	HINIC_PRINT("Device %s link status change from %s to %s",
		    nic_dev->proc_dev_name,
		    (old_link.link_status ? "UP" : "DOWN"),
		    (new_link.link_status ? "UP" : "DOWN"));

	return HINIC_OK;
}

/**
 * DPDK callback to enable promiscuous mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void hinic_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	int rc = HINIC_OK;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	HINIC_PRINT("Enable promiscuous, nic_dev: %s, port_id: %d, promisc: %d",
		    nic_dev->proc_dev_name, dev->data->port_id,
		    dev->data->promiscuous);

	rc = hinic_priv_set_dev_promiscuous(nic_dev, true);
	if(rc != HINIC_OK)
		HINIC_PRINT_ERR("Enable promiscuous failed, error: %d", rc);
}

/**
 * DPDK callback to disable promiscuous mode.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
void hinic_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	int rc = HINIC_OK;
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);

	HINIC_PRINT("Disable promiscuous, nic_dev: %s, port_id: %d, promisc: %d",
		    nic_dev->proc_dev_name, dev->data->port_id,
		    dev->data->promiscuous);

	rc = hinic_priv_set_dev_promiscuous(nic_dev, false);
	if(HINIC_OK != rc)
		HINIC_PRINT_ERR("Disable promiscuous failed, error: %d", rc);
}

int hinic_link_event_process(struct rte_eth_dev *dev, u8 status)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	uint32_t port_speed[LINK_SPEED_MAX] = {ETH_SPEED_NUM_10M,
					ETH_SPEED_NUM_100M, ETH_SPEED_NUM_1G,
					ETH_SPEED_NUM_10G, ETH_SPEED_NUM_25G,
					ETH_SPEED_NUM_40G, ETH_SPEED_NUM_100G};
	struct nic_port_info port_info;
	struct rte_eth_link link;
	int rc = HINIC_OK;

	nic_dev->link_status = status;
	if (!status) {
		link.link_status = ETH_LINK_DOWN;
		link.link_speed = 0;
		link.link_duplex = ETH_LINK_HALF_DUPLEX;
		link.link_autoneg = ETH_LINK_FIXED;
	} else {
		link.link_status = ETH_LINK_UP;

		memset(&port_info, 0, sizeof(port_info));
		rc = hinic_get_port_info(nic_dev->hwdev, &port_info);
		if (rc) {
			link.link_speed = ETH_SPEED_NUM_NONE;
			link.link_duplex = ETH_LINK_FULL_DUPLEX;
			link.link_autoneg = ETH_LINK_FIXED;
		} else {
			link.link_speed = port_speed[port_info.speed %
						LINK_SPEED_MAX];
			link.link_duplex = port_info.duplex;
			link.link_autoneg = port_info.autoneg_state;
		}
	}

	(void)hinic_dev_atomic_write_link_status(dev, &link);

	return rc;
}

/**
 * DPDK callback to update the RSS hash key and RSS hash type.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param rss_conf
 *   RSS configuration data.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
int hinic_rss_hash_update(struct rte_eth_dev *dev,
			  struct rte_eth_rss_conf *rss_conf)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	u8 tmpl_idx = nic_dev->rss_tmpl_idx;
	u8 hashkey[HINIC_RSS_KEY_SIZE] = {0};
	u8 prio_tc[HINIC_DCB_UP_MAX] = {0};
	u64 rss_hf = rss_conf->rss_hf;
	struct nic_rss_type rss_type = {0};
	int err = 0;

	HINIC_PRINT("rss info, rss_flag:0x%x, rss_key_len:%d, rss_hf:%lu, tmpl_idx:%d",
		    nic_dev->flags, rss_conf->rss_key_len, rss_hf, tmpl_idx);

	if (!(nic_dev->flags & ETH_MQ_RX_RSS_FLAG)) {
		HINIC_PRINT("RSS is not enabled");
		return HINIC_OK;
	}

	if (rss_conf->rss_key_len > HINIC_RSS_KEY_SIZE) {
		HINIC_PRINT_ERR("Invalid rss key, rss_key_len:%d\n",
				rss_conf->rss_key_len);
		return HINIC_ERROR;
	}

	if (rss_conf->rss_key) {
		memcpy(hashkey, rss_conf->rss_key, rss_conf->rss_key_len);
		err = hinic_rss_set_template_tbl(nic_dev->hwdev, tmpl_idx,
						 hashkey);
		if (err) {
			HINIC_PRINT_ERR("Set rss template table failed, error:%d",
					err);
			goto disable_rss;
		}
	}

	rss_type.ipv4 = (rss_hf & (ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4)) ? 1 : 0;
	rss_type.tcp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_TCP) ? 1 : 0;
	rss_type.ipv6 = (rss_hf & (ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6)) ? 1 : 0;
	rss_type.ipv6_ext = (rss_hf & ETH_RSS_IPV6_EX) ? 1 : 0;
	rss_type.tcp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_TCP) ? 1 : 0;
	rss_type.tcp_ipv6_ext = (rss_hf & ETH_RSS_IPV6_TCP_EX) ? 1 : 0;
	rss_type.udp_ipv4 = (rss_hf & ETH_RSS_NONFRAG_IPV4_UDP) ? 1 : 0;
	rss_type.udp_ipv6 = (rss_hf & ETH_RSS_NONFRAG_IPV6_UDP) ? 1 : 0;

	err = hinic_set_rss_type(nic_dev->hwdev, tmpl_idx, rss_type);
	if (err) {
		HINIC_PRINT_ERR("Set rss type table failed, error:%d", err);
		goto disable_rss;
	}

	return HINIC_OK;

disable_rss:
	memset(prio_tc, 0, sizeof(prio_tc));
	(void)hinic_rss_cfg(nic_dev->hwdev, 0, tmpl_idx, 0, prio_tc);
	return err;
}

/**
 * DPDK callback to get the RSS hash configuration.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param rss_conf
 *   RSS configuration data.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
int hinic_rss_conf_get(struct rte_eth_dev *dev,
		       struct rte_eth_rss_conf *rss_conf)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	u8 tmpl_idx = nic_dev->rss_tmpl_idx;
	u8 hashkey[HINIC_RSS_KEY_SIZE] = {0};
	struct nic_rss_type rss_type = {0};
	int err;

	if (!(nic_dev->flags & ETH_MQ_RX_RSS_FLAG)) {
		HINIC_PRINT("RSS is not enabled");
		return HINIC_ERROR;
	}

	err = hinic_rss_get_template_tbl(nic_dev->hwdev, tmpl_idx, hashkey);
	if (err) {
		HINIC_PRINT_ERR("Get rss template failed, error:%d", err);
		return err;
	}

	if (rss_conf->rss_key &&
	    rss_conf->rss_key_len >= HINIC_RSS_KEY_SIZE) {
		memcpy(rss_conf->rss_key, hashkey, sizeof(hashkey));
		rss_conf->rss_key_len = sizeof(hashkey);
	}

	err = hinic_get_rss_type(nic_dev->hwdev, tmpl_idx, &rss_type);
	if (err) {
		HINIC_PRINT_ERR("Get rss type failed, error:%d", err);
		return err;
	}

	rss_conf->rss_hf = 0;
	rss_conf->rss_hf |=  rss_type.ipv4 ?
		(ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4) : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv4 ? ETH_RSS_NONFRAG_IPV4_TCP : 0;
	rss_conf->rss_hf |=  rss_type.ipv6 ?
		(ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6) : 0;
	rss_conf->rss_hf |=  rss_type.ipv6_ext ? ETH_RSS_IPV6_EX : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv6 ? ETH_RSS_NONFRAG_IPV6_TCP : 0;
	rss_conf->rss_hf |=  rss_type.tcp_ipv6_ext ? ETH_RSS_IPV6_TCP_EX : 0;
	rss_conf->rss_hf |=  rss_type.udp_ipv4 ? ETH_RSS_NONFRAG_IPV4_UDP : 0;
	rss_conf->rss_hf |=  rss_type.udp_ipv6 ? ETH_RSS_NONFRAG_IPV6_UDP : 0;

	return HINIC_OK;
}

/**
 * DPDK callback to update the RETA indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param reta_conf
 *   Pointer to RETA configuration structure array.
 * @param reta_size
 *   Size of the RETA table.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
int hinic_rss_indirtbl_update(struct rte_eth_dev *dev,
			      struct rte_eth_rss_reta_entry64 *reta_conf,
			      uint16_t reta_size)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	u8 tmpl_idx = nic_dev->rss_tmpl_idx;
	u8 prio_tc[HINIC_DCB_UP_MAX] = {0};
	u32 indirtbl[NIC_RSS_INDIR_SIZE] = {0};
	int err = 0;
	u16 i = 0;
	u16 idx, shift;

	HINIC_PRINT("Update indirect table, rss_flag:0x%x, reta_size:%d, tmpl_idx:%d",
		    nic_dev->flags, reta_size, tmpl_idx);

	if (!(nic_dev->flags & ETH_MQ_RX_RSS_FLAG))
		return HINIC_OK;

	if (reta_size != NIC_RSS_INDIR_SIZE) {
		HINIC_PRINT_ERR("Invalid reta size, reta_size:%d", reta_size);
		return HINIC_ERROR;
	}

	err = hinic_rss_get_indir_tbl(nic_dev->hwdev, tmpl_idx, indirtbl);
	if (err) {
		HINIC_PRINT_ERR("Get rss indirect table failed, error:%d", err);
		return err;
	}

	/* update rss indir_tbl */
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			indirtbl[i] = reta_conf[idx].reta[shift];
	}

	for (i = 0 ; i < reta_size; i++) {
		if (indirtbl[i] >= nic_dev->num_rq) {
			HINIC_PRINT_ERR("Invalid reta entry, index:%d, num_rq:%d",
					i, nic_dev->num_rq);
			goto disable_rss;
		}
	}

	err = hinic_rss_set_indir_tbl(nic_dev->hwdev, tmpl_idx, indirtbl);
	if (err) {
		HINIC_PRINT_ERR("Set indirect table failed, error:%d", err);
		goto disable_rss;
	}

	nic_dev->rss_indir_flag = true;
	HINIC_DEBUG("Update indirect table success");

	return HINIC_OK;

disable_rss:
	memset(prio_tc, 0, sizeof(prio_tc));
	(void)hinic_rss_cfg(nic_dev->hwdev, 0, tmpl_idx, 0, prio_tc);

	return HINIC_ERROR;
}


/**
 * DPDK callback to get the RETA indirection table.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param reta_conf
 *   Pointer to RETA configuration structure array.
 * @param reta_size
 *   Size of the RETA table.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
int hinic_rss_indirtbl_query(struct rte_eth_dev *dev,
			     struct rte_eth_rss_reta_entry64 *reta_conf,
			     uint16_t reta_size)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	u8 tmpl_idx = nic_dev->rss_tmpl_idx;
	int err = 0;
	u32 indirtbl[NIC_RSS_INDIR_SIZE] = {0};
	u16 idx, shift;
	u16 i = 0;

	if (reta_size != NIC_RSS_INDIR_SIZE) {
		HINIC_PRINT_ERR("Invalid reta size, reta_size:%d", reta_size);
		return HINIC_ERROR;
	}

	err = hinic_rss_get_indir_tbl(nic_dev->hwdev, tmpl_idx, indirtbl);
	if (err) {
		HINIC_PRINT_ERR("Get rss indirect table failed, error:%d",
				err);
		return err;
	}

	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta_conf[idx].reta[shift] = (uint16_t)indirtbl[i];
	}

	return HINIC_OK;
}

/**
 * DPDK callback to get extended device statistics.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param xstats
 *   Pointer to rte extended stats table.
 * @param n
 *   The size of the stats table.
 *
 * @return
 *   Number of extended stats on success and stats is filled,
 *   negative error value otherwise.
 */
int hinic_dev_xstats_get(struct rte_eth_dev *dev,
			 struct rte_eth_xstat *xstats,
			 unsigned int n)
{
	u16 qid = 0;
	u32 i;
	int err, func_id, count;
	hinic_nic_dev *nic_dev;
	struct hinic_phy_port_stats port_stats;
	struct hinic_vport_stats vport_stats;
	struct hinic_rxq	*rxq = NULL;
	struct hinic_rxq_stats rxq_stats;
	struct hinic_txq	*txq = NULL;
	struct hinic_txq_stats txq_stats;

	nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	count = hinic_xstats_calc_num(nic_dev);
	if ((int)n < count)
		return count;

	count = 0;

	/* Get stats from hinic_rxq_stats */
	for (qid = 0; qid < nic_dev->num_rq; qid++) {
		rxq = nic_dev->rxqs[qid];
		hinic_rxq_get_stats(rxq, &rxq_stats);

		for (i = 0; i < HINIC_RXQ_XSTATS_NUM; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)&rxq_stats) +
				hinic_rxq_stats_strings[i].offset);
			xstats[count].id = count;
			count++;
		}
	}

	/* Get stats from hinic_txq_stats */
	for (qid = 0; qid < nic_dev->num_sq; qid++) {
		txq = nic_dev->txqs[qid];
		hinic_txq_get_stats(txq, &txq_stats);

		for (i = 0; i < HINIC_TXQ_XSTATS_NUM; i++) {
			xstats[count].value =
				*(uint64_t *)(((char *)&txq_stats) +
				hinic_txq_stats_strings[i].offset);
			xstats[count].id = count;
			count++;
		}
	}

	func_id = hinic_global_func_id(nic_dev->hwdev);
	HINIC_ERR_RET(nic_dev, !xstats, 0,
		      "Invalid xstats args, func_id: %d",
		      func_id);

	/* Get stats from hinic_vport_stats */
	err = hinic_get_vport_stats(nic_dev->hwdev, &vport_stats);
	HINIC_ERR_RET(nic_dev, err, 0,
		      "Get vport stats from fw failed, func_id: %d",
		      func_id);

	for (i = 0; i < HINIC_VPORT_XSTATS_NUM; i++) {
		xstats[count].value =
			*(uint64_t *)(((char *)&vport_stats) +
			hinic_vport_stats_strings[i].offset);
		xstats[count].id = count;
		count++;
	}

	/* Get stats from hinic_phy_port_stats */
	err = hinic_get_phy_port_stats(nic_dev->hwdev, &port_stats);
	HINIC_ERR_RET(nic_dev, err, count,
		      "Get phy port stats from fw failed, func_id: %d",
		      func_id);

	for (i = 0; i < HINIC_PHYPORT_XSTATS_NUM; i++) {
		xstats[count].value = *(uint64_t *)(((char *)&port_stats) +
				hinic_phyport_stats_strings[i].offset);
		xstats[count].id = count;
		count++;
	}

	return count;
}

/**
 * DPDK callback to retrieve names of extended device statistics
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param xstats_names
 *   Buffer to insert names into.
 * @param n
 *   Number of names.
 *
 * @return
 *   Number of xstats names.
 */
int hinic_dev_xstats_get_names(struct rte_eth_dev *dev,
			       struct rte_eth_xstat_name *xstats_names,
			       __rte_unused unsigned int limit)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	int count = 0;
	u16 i = 0, q_num;

	if (xstats_names == NULL)
		return hinic_xstats_calc_num(nic_dev);

	/* get pmd rxq stats */
	for (q_num = 0; q_num < nic_dev->num_rq; q_num++) {
		for (i = 0; i < HINIC_RXQ_XSTATS_NUM; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "rxq%d_%s_pmd",
				 q_num, hinic_rxq_stats_strings[i].name);
			count++;
		}
	}

	/* get pmd txq stats */
	for (q_num = 0; q_num < nic_dev->num_sq; q_num++) {
		for (i = 0; i < HINIC_TXQ_XSTATS_NUM; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "txq%d_%s_pmd",
				 q_num, hinic_txq_stats_strings[i].name);
			count++;
		}
	}

	/* get vport stats */
	for (i = 0; i < HINIC_VPORT_XSTATS_NUM; i++) {
		snprintf(xstats_names[count].name,
			 sizeof(xstats_names[count].name),
			 "%s",
			 hinic_vport_stats_strings[i].name);
		count++;
	}

	/* get phy port stats */
	for (i = 0; i < HINIC_PHYPORT_XSTATS_NUM; i++) {
		snprintf(xstats_names[count].name,
			 sizeof(xstats_names[count].name),
			 "%s",
			 hinic_phyport_stats_strings[i].name);
		count++;
	}

	return count;
}

/**
 * DPDK callback to get fw version
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param fw_version
 *   Pointer to fw version structure.
 * @param fw_size
 *   Size of fw version.
 *
 * @return
 *   Number of xstats names.
 */
int
hinic_fw_version_get(struct rte_eth_dev *dev, char *fw_version, size_t fw_size)
{
	hinic_nic_dev *nic_dev = HINIC_DEV_PRIVATE_TO_NIC_DEV(dev);
	struct hinic_fw_version fw_ver;
	int ret;

	memset(&fw_ver, 0, sizeof(fw_ver));
	ret = hinic_get_fw_version(nic_dev->hwdev, &fw_ver);
	if (ret) {
		HINIC_PRINT_ERR("Get fw version failed, error:%d", ret);
		return ret;
	}

	ret = snprintf(fw_version, fw_size, "%s", fw_ver.microcode_ver);
	ret += 1; /* add the size of '\0' */
	if (fw_size < (u32)ret)
		return ret;
	else
		return 0;
}
