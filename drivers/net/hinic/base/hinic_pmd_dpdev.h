/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_DPDEV_H_
#define _HINIC_PMD_DPDEV_H_

#include <rte_ethdev.h>
#include <rte_eth_ctrl.h>

#include "hinic_compat.h"
#include "hinic_csr.h"
#include "hinic_ctx_def.h"
#include "hinic_qe_def.h"
#include "hinic_port_cmd.h"
#include "hinic_pmd_wq.h"
#include "hinic_pmd_hw.h"
#include "hinic_pmd_hw_mgmt.h"
#include "hinic_pmd_hwif.h"
#include "hinic_pmd_nicio.h"
#include "hinic_pmd_qp.h"
#include "hinic_pmd_hwdev.h"
#include "hinic_pmd_nic.h"
#include "hinic_pmd_niccfg.h"
#include "hinic_pmd_mgmt_interface.h"
#include "hinic_pmd_cfg.h"
#include "hinic_pmd_eqs.h"
#include "hinic_pmd_api_cmd.h"
#include "hinic_pmd_mgmt.h"
#include "hinic_pmd_cmdq.h"

#define HINIC_AEQN_START	(0)
#define HINIC_AEQN_NUM		(4)
#define HINIC_MGMT_RSP_AEQN	(1)

#define HINIC_DEV_NAME_LEN	(32)

#define HINIC_MAX_DMA_ENTRIES	(8192)

#define HINIC_MAX_RX_QUEUES	(64)

#define HINIC_MGMT_CMD_UNSUPPORTED	0xFF

/* mbuf pool for copy invalid mbuf segs */
#define HINIC_COPY_MEMPOOL_DEPTH (128)
#define HINIC_COPY_MBUF_SIZE     (4096)

#define HINIC_DEV_PRIVATE_TO_NIC_DEV(dev) \
	((hinic_nic_dev *)(dev)->data->dev_private)

#define HINIC_HWDEV_DRV_MODE(hwdev)	\
	(((hinic_nic_dev *)((struct hinic_hwdev *)hwdev)->dev_hdl)->drv_mode)

enum hinic_dev_status {
	HINIC_DEV_INIT,
	HINIC_DEV_CLOSE,
	HINIC_DEV_START,
	HINIC_DEV_INTR_EN,
};

struct hinic_txq;
struct hinic_rxq;

/* dma os dependency implementation */
struct hinic_os_dep {
	/* kernel dma alloc api */
	rte_atomic32_t dma_alloc_cnt;
	rte_spinlock_t  dma_hash_lock;
	struct rte_hash *dma_addr_hash;
};

/* hinic nic_device */
typedef struct tag_hinic_nic_dev {
	u32 link_status;		/* port link status */
	struct hinic_txq **txqs;
	struct hinic_rxq **rxqs;
	struct rte_mempool *cpy_mpool;
	u16 num_qps;
	u16 num_sq;
	u16 num_rq;
	u16 mtu_size;
	u8 rss_tmpl_idx;
	u8 rss_indir_flag;
	u8 num_rss;
	u8 rx_queue_list[HINIC_MAX_RX_QUEUES];

	/* hardware hw_dev */
	struct hinic_hwdev *hwdev;
	struct hinic_nic_io *nic_io;

	/* dma memory allocator */
	struct hinic_os_dep dumb_os_dep;
	struct hinic_os_dep *os_dep;

	/* info */
	unsigned int flags;
	struct nic_service_cap nic_cap;
	u32 rx_mode_status;	/* promisc allmulticast */
	unsigned long dev_status;

	/* dpdk only */
	char proc_dev_name[HINIC_DEV_NAME_LEN];
	/* PF0->COS4, PF1->COS5, PF2->COS6, PF3->COS7,
	 * vf: the same with associate pf
	 */
	u32 default_cos;

	u32 ffm_num;
}hinic_nic_dev;

int32_t hinic_nic_dev_create(struct rte_eth_dev *rte_dev);
void hinic_nic_dev_destroy(struct rte_eth_dev *rte_dev);

int hinic_hwif_res_init(hinic_nic_dev *nic_dev);
void hinic_hwif_res_free(hinic_nic_dev *nic_dev);

int hinic_init_nicio(hinic_nic_dev *nic_dev);
void hinic_deinit_nicio(hinic_nic_dev *nic_dev);

int hinic_comm_aeqs_init(hinic_nic_dev *nic_dev);
void hinic_comm_aeqs_free(hinic_nic_dev *nic_dev);

int hinic_comm_pf_to_mgmt_init(hinic_nic_dev *nic_dev);
void hinic_comm_pf_to_mgmt_free(hinic_nic_dev *nic_dev);

int hinic_comm_cmdqs_init(struct hinic_hwdev *hwdev);
void hinic_comm_cmdqs_free(struct hinic_hwdev *hwdev);

int hinic_init_capability(hinic_nic_dev *nic_dev);

int hinic_create_rq(hinic_nic_dev *nic_dev, u16 q_id, u16 rq_depth);
void hinic_destroy_rq(hinic_nic_dev *nic_dev, u16 q_id);

int hinic_create_sq(hinic_nic_dev *nic_dev, u16 q_id, u16 sq_depth);
void hinic_destroy_sq(hinic_nic_dev *nic_dev, u16 q_id);

void hinic_lsc_process(struct rte_eth_dev *rte_dev, u8 status);

void *hinic_dma_mem_zalloc(void *dev, size_t size, dma_addr_t *dma_handle,
		unsigned int flag, unsigned int align);
void hinic_dma_mem_free(void *dev, size_t size, void *virt, dma_addr_t phys);

int hinic_init_sw_rxtxqs(hinic_nic_dev *nic_dev);
void hinic_deinit_sw_rxtxqs(hinic_nic_dev *nic_dev);

void dma_free_coherent_volatile(void *dev, size_t size,
	volatile void *virt, dma_addr_t phys);

#endif /* _HINIC_PMD_DPDEV_H_ */