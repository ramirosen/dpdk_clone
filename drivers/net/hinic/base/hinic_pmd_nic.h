/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_NIC_H_
#define _HINIC_PMD_NIC_H_

#define HINIC_FLUSH_QUEUE_TIMEOUT 3000

struct hinic_hwdev;
struct hinic_wq;

struct hinic_sq {
	struct hinic_wq		*wq;
	volatile u16		*cons_idx_addr;
	void __iomem		*db_addr;

	u16	q_id;
	u16	owner;
	u16	sq_depth;
};

struct hinic_rq {
	struct hinic_wq		*wq;
	volatile u16		*pi_virt_addr;
	dma_addr_t		pi_dma_addr;

	u16			irq_id;
	u16			msix_entry_idx;
	u16			q_id;
	u16			rq_depth;
};

struct hinic_qp {
	struct hinic_sq		sq;
	struct hinic_rq		rq;
};

struct vf_data_storage {
	u8 vf_mac_addr[ETH_ALEN];
	bool registered;
	bool pf_set_mac;
	u16 pf_vlan;
	u8 pf_qos;

	bool link_forced;
	bool link_up;		/* only valid if VF link is forced */
};

struct hinic_nic_io {
	struct hinic_hwdev	*hwdev;

	u16			global_qpn;
	u8			link_status;

	struct hinic_wq		*sq_wq;
	struct hinic_wq		*rq_wq;

	u16			max_qps;
	u16			num_qps;

	u16			num_sqs;
	u16			num_rqs;

	u16			sq_depth;
	u16			rq_depth;

	u16			rq_buf_size;
	u16			vhd_mode;

	struct hinic_qp		*qps;
	/* sq ci mem base addr of the function*/
	void			*ci_vaddr_base;
	dma_addr_t		ci_dma_base;

	struct hinic_event	event;
	void			*event_handle;

	u16			max_vfs;
	u16			num_vfs;
	u8			vf_link_mode;
	struct vf_data_storage	*vf_infos;
};

#endif /* _HINIC_PMD_NIC_H_ */