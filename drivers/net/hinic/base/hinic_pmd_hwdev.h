/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_HWDEV_H_
#define _HINIC_PMD_HWDEV_H_

#define HINIC_PAGE_SIZE_MAX	20
#define HINIC_PAGE_SIZE_DPDK	6

#define HINIC_PCIE_LINK_DOWN		0xFFFFFFFF

#define HINIC_DEV_ACTIVE_FW_TIMEOUT	(35 * 1000)
#define HINIC_DEV_BUSY_ACTIVE_FW	0xFE

struct hinic_page_addr {
	void *virt_addr;
	u64 phys_addr;
};

struct nic_interrupt_info {
	u32 lli_set;
	u32 interrupt_coalesc_set;
	u16 msix_index;
	u8 lli_credit_limit;
	u8 lli_timer_cfg;
	u8 pending_limt;
	u8 coalesc_timer_cfg;
	u8 resend_timer_cfg;
};

struct hinic_sq_attr {
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	/* bit[63:2] is addr's high 62bit, bit[0] is valid flag */
	u64 ci_dma_base;
};

struct hinic_board_info {
	u32	board_type;
	u32	port_num;
	u32	port_speed;
	u32	pcie_width;
	u32	host_num;
	u32	pf_num;
	u32	vf_total_num;
	u32	tile_num;
	u32	qcm_num;
	u32	core_num;
	u32	work_mode;
	u32	service_mode;
	u32	pcie_mode;
	u32	cfg_addr;
	u32	boot_sel;
};

/* defined by chip */
enum hinic_fault_type {
	FAULT_TYPE_CHIP,
	FAULT_TYPE_UCODE,
	FAULT_TYPE_MEM_RD_TIMEOUT,
	FAULT_TYPE_MEM_WR_TIMEOUT,
	FAULT_TYPE_REG_RD_TIMEOUT,
	FAULT_TYPE_REG_WR_TIMEOUT,
	FAULT_TYPE_MAX,
};

/* defined by chip */
enum hinic_fault_err_level {
	/* default err_level=FAULT_LEVEL_FATAL if
	 * type==FAULT_TYPE_MEM_RD_TIMEOUT || FAULT_TYPE_MEM_WR_TIMEOUT ||
	 *	 FAULT_TYPE_REG_RD_TIMEOUT || FAULT_TYPE_REG_WR_TIMEOUT ||
	 *	 FAULT_TYPE_UCODE
	 * other: err_level in event.chip.err_level if type==FAULT_TYPE_CHIP
	 */
	FAULT_LEVEL_FATAL,
	FAULT_LEVEL_SERIOUS_RESET,
	FAULT_LEVEL_SERIOUS_FLR,
	FAULT_LEVEL_GENERAL,
	FAULT_LEVEL_SUGGESTION,
	FAULT_LEVEL_MAX
};

/* defined by chip */
struct hinic_fault_event {
	/* enum hinic_fault_type */
	u8 type;
	u8 rsvd0[3];
	union {
		u32 val[4];
		/* valid only type==FAULT_TYPE_CHIP */
		struct {
			u8 node_id;
			/* enum hinic_fault_err_level */
			u8 err_level;
			u8 err_type;
			u8 rsvd1;
			u32 err_csr_addr;
			u32 err_csr_value;
		/* func_id valid only err_level==FAULT_LEVEL_SERIOUS_FLR */
			u16 func_id;
			u16 rsvd2;
		} chip;

		/* valid only type==FAULT_TYPE_UCODE */
		struct {
			u8 cause_id;
			u8 core_id;
			u8 c_id;
			u8 rsvd3;
			u32 epc;
			u32 rsvd4;
			u32 rsvd5;
		} ucode;

		/* valid only type==FAULT_TYPE_MEM_RD_TIMEOUT ||
		 *		FAULT_TYPE_MEM_WR_TIMEOUT
		 */
		struct {
			u32 err_csr_ctrl;
			u32 err_csr_data;
			u32 ctrl_tab;
			u32 mem_index;
		} mem_timeout;

		/* valid only type==FAULT_TYPE_REG_RD_TIMEOUT ||
		 *		    FAULT_TYPE_REG_WR_TIMEOUT
		 */
		struct {
			u32 err_csr;
			u32 rsvd6;
			u32 rsvd7;
			u32 rsvd8;
		} reg_timeout;
	} event;
};

typedef struct tag_hinic_nic_dev hinic_nic_dev;

struct hinic_hwdev {
	struct rte_pci_device *pcidev_hdl;
	hinic_nic_dev *dev_hdl;

	struct hinic_hwif *hwif;

	struct hinic_nic_io *nic_io;
	struct cfg_mgmt_info *cfg_mgmt;

	struct hinic_aeqs *aeqs;

	struct hinic_mbox_func_to_func *func_to_func;

	struct hinic_msg_pf_to_mgmt *pf_to_mgmt;

	struct hinic_cmdqs *cmdqs;

	struct hinic_page_addr page_pa0;
	struct hinic_page_addr page_pa1;
};

int hinic_get_board_info(void *hwdev, struct hinic_board_info *info);

int hinic_set_ci_table(void *hwdev, u16 q_id, struct hinic_sq_attr *attr);

int hinic_set_root_ctxt(void *hwdev, u16 rq_depth, u16 sq_depth, int rx_buf_sz);
int hinic_clean_root_ctxt(void *hwdev);

int hinic_func_rx_tx_flush(struct hinic_hwdev *hwdev);

int hinic_set_interrupt_cfg(struct hinic_hwdev *hwdev,
			    struct nic_interrupt_info interrupt_info);

void hinic_misx_intr_clear_resend_bit(void *hwdev, u16 msix_idx,
				      u8 clear_resend_en);

int init_aeqs_msix_attr(void *hwdev);

int hinic_msg_to_mgmt_sync(void *hwdev, enum hinic_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size, u32 timeout);

void hinic_comm_async_event_handle(struct hinic_hwdev *hwdev, u8 cmd,
				   void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size);

void hinic_l2nic_async_event_handle(struct hinic_hwdev *hwdev, void *param,
				    u8 cmd, void *buf_in, u16 in_size,
				    void *buf_out, u16 *out_size);

void hinic_hilink_async_event_handle(struct hinic_hwdev *hwdev, u8 cmd,
				     void *buf_in, u16 in_size, void *buf_out,
				     u16 *out_size);

int hinic_init_attr_table(struct hinic_hwdev *hwdev);

int hinic_activate_hwdev_state(struct hinic_hwdev *hwdev);
void hinic_deactivate_hwdev_state(struct hinic_hwdev *hwdev);

int hinic_l2nic_reset(struct hinic_hwdev *hwdev);

int hinic_convert_rx_buf_size(u32 rx_buf_sz, u32 *match_sz);

#endif /* _HINIC_PMD_HWDEV_H_ */
