/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"

#define HINIC_DEAULT_EQ_MSIX_PENDING_LIMIT	0
#define HINIC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG	0xFF
#define HINIC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG	7

#define HINIC_FLR_TIMEOUT			1000

#define HINIC_MGMT_CHANNEL_STATUS_SHIFT		0x0
#define HINIC_MGMT_CHANNEL_STATUS_MASK		0x1

#define FFM_RECORD_NUM_MAX			32

#define	HINIC_MSIX_CNT_RESEND_TIMER_SHIFT	29
#define	HINIC_MSIX_CNT_RESEND_TIMER_MASK	0x7U

#define HINIC_MSIX_CNT_SET(val, member)		\
		(((val) & HINIC_MSIX_CNT_##member##_MASK) << \
		HINIC_MSIX_CNT_##member##_SHIFT)

#define HINIC_GET_MGMT_CHANNEL_STATUS(val, member)	\
	(((val) >> HINIC_##member##_SHIFT) & HINIC_##member##_MASK)

struct hinic_cons_idx_attr {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u8	dma_attr_off;
	u8	pending_limit;
	u8	coalescing_time;
	u8	intr_en;
	u16	intr_idx;
	u32	l2nic_sqn;
	u32	sq_id;
	u64	ci_addr;
};

struct hinic_clear_doorbell {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u8	ppf_idx;
	u8	rsvd1;
};

struct hinic_clear_resource {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u8	ppf_idx;
	u8	rsvd1;
};

struct hinic_cmd_set_res_state {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u8	state;
	u8	rsvd1;
	u32	rsvd2;
};

const int hinic_hw_rx_buf_size[] = {
	HINIC_RX_BUF_SIZE_32B,
	HINIC_RX_BUF_SIZE_64B,
	HINIC_RX_BUF_SIZE_96B,
	HINIC_RX_BUF_SIZE_128B,
	HINIC_RX_BUF_SIZE_192B,
	HINIC_RX_BUF_SIZE_256B,
	HINIC_RX_BUF_SIZE_384B,
	HINIC_RX_BUF_SIZE_512B,
	HINIC_RX_BUF_SIZE_768B,
	HINIC_RX_BUF_SIZE_1K,
	HINIC_RX_BUF_SIZE_1_5K,
	HINIC_RX_BUF_SIZE_2K,
	HINIC_RX_BUF_SIZE_3K,
	HINIC_RX_BUF_SIZE_4K,
	HINIC_RX_BUF_SIZE_8K,
	HINIC_RX_BUF_SIZE_16K,
};

struct hinic_msix_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	msix_index;
	u8	pending_cnt;
	u8	coalesct_timer_cnt;
	u8	lli_tmier_cnt;
	u8	lli_credit_cnt;
	u8	resend_timer_cnt;
	u8	rsvd1[3];
};

struct hinic_cmd_fault_event {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	struct hinic_fault_event event;
};

struct hinic_mgmt_watchdog_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u32 curr_time_h;
	u32 curr_time_l;
	u32 task_id;
	u32 rsv;

	u32 reg[13];
	u32 pc;
	u32 lr;
	u32 cpsr;

	u32 stack_top;
	u32 stack_bottom;
	u32 sp;
	u32 curr_used;
	u32 peak_used;
	u32 is_overflow;

	u32 stack_actlen;
	u8 data[1024];
};

#define MAX_PCIE_DFX_BUF_SIZE (1024)

struct hinic_pcie_dfx_ntc {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	int len;
	u32 rsvd;
};

struct hinic_pcie_dfx_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u8 host_id;
	u8 last;
	u8 rsvd[2];
	u32 offset;

	u8 data[MAX_PCIE_DFX_BUF_SIZE];
};

struct ffm_intr_info {
	u8 node_id;
	/* error level of the interrupt source */
	u8 err_level;
	/* Classification by interrupt source properties */
	u16 err_type;
	u32 err_csr_addr;
	u32 err_csr_value;
};

struct hinic_comm_board_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	struct hinic_board_info info;

	u32	rsvd1[5];
};

struct hi30_ctle_data {
	u8 ctlebst[3];
	u8 ctlecmband[3];
	u8 ctlermband[3];
	u8 ctleza[3];
	u8 ctlesqh[3];
	u8 ctleactgn[3];
	u8 ctlepassgn;
};

struct hi30_ffe_data {
	u8 PRE2;
	u8 PRE1;
	u8 POST1;
	u8 POST2;
	u8 MAIN;
};

struct hinic_link_info {
	u8	vendor_name[16];
	/* port type:
	 * 1 - fiber; 2 - electric; 3 - copper; 4 - AOC; 5 - backplane;
	 * 6 - baseT; 0xffff - unknown
	 *
	 * port subtype:
	 * Only when port_type is fiber:
	 * 1 - SR; 2 - LR
	 */
	u32	port_type;
	u32	port_sub_type;
	u32	cable_length;
	u8	cable_temp;
	u8	cable_max_speed;/* 1(G)/10(G)/25(G)... */
	u8	sfp_type;	/* 0 - qsfp; 1 - sfp */
	u8	rsvd0;
	u32	power[4];	/* uW; if is sfp, only power[2] is valid */

	u8	an_state;	/* 0 - off; 1 - on */
	u8	fec;		/* 0 - RSFEC; 1 - BASEFEC; 2 - NOFEC */
	u16	speed;		/* 1(G)/10(G)/25(G)... */

	u8	cable_absent;	/* 0 - cable present; 1 - cable unpresent */
	u8	alos;		/* 0 - yes; 1 - no */
	u8	rx_los;		/* 0 - yes; 1 - no */
	u8	pma_status;
	u32	pma_dbg_info_reg;	/* pma debug info: */
	u32	pma_signal_ok_reg;	/* signal ok: */

	u32	pcs_err_blk_cnt_reg;	/* error block counter: */
	u32	rf_lf_status_reg;	/* RF/LF status: */
	u8	pcs_link_reg;		/* pcs link: */
	u8	mac_link_reg;		/* mac link: */
	u8	mac_tx_en;
	u8	mac_rx_en;
	u32	pcs_err_cnt;

	u8	lane_used;
	u8	hi30_ffe[5];
	u8	hi30_ctle[19];
	u8	hi30_dfe[14];
	u8	rsvd4;
};

struct hinic_hilink_link_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	port_id;
	u8	info_type;	/* 1: link up  2: link down  3 cable plugged */
	u8	rsvd1;

	struct hinic_link_info info;

	u8	rsvd2[780];
};

enum hinic_link_port_type {
	LINK_PORT_FIBRE	= 1,
	LINK_PORT_ELECTRIC,
	LINK_PORT_COPPER,
	LINK_PORT_AOC,
	LINK_PORT_BACKPLANE,
	LINK_PORT_BASET,
	LINK_PORT_MAX_TYPE,
};

enum hilink_fibre_subtype {
	FIBRE_SUBTYPE_SR = 1,
	FIBRE_SUBTYPE_LR,
	FIBRE_SUBTYPE_MAX,
};

enum hilink_fec_type {
	HILINK_FEC_RSFEC,
	HILINK_FEC_BASEFEC,
	HILINK_FEC_NOFEC,
	HILINK_FEC_MAX_TYPE,
};

static const char *__hw_to_char_fec[HILINK_FEC_MAX_TYPE] = {
	"RS-FEC", "BASE-FEC", "NO-FEC"};

static const char *__hw_to_char_port_type[LINK_PORT_MAX_TYPE] = {
	"Unknown", "Fibre", "Electric", "Direct Attach Copper", "AOC",
	"Back plane", "BaseT"
};

static const char *hinic_module_link_err[LINK_ERR_NUM] = {
	"Unrecognized module",
};

#define HINIC_DMA_ATTR_ENTRY_ST_SHIFT				0
#define HINIC_DMA_ATTR_ENTRY_AT_SHIFT				8
#define HINIC_DMA_ATTR_ENTRY_PH_SHIFT				10
#define HINIC_DMA_ATTR_ENTRY_NO_SNOOPING_SHIFT			12
#define HINIC_DMA_ATTR_ENTRY_TPH_EN_SHIFT			13

#define HINIC_DMA_ATTR_ENTRY_ST_MASK				0xFF
#define HINIC_DMA_ATTR_ENTRY_AT_MASK				0x3
#define HINIC_DMA_ATTR_ENTRY_PH_MASK				0x3
#define HINIC_DMA_ATTR_ENTRY_NO_SNOOPING_MASK			0x1
#define HINIC_DMA_ATTR_ENTRY_TPH_EN_MASK			0x1

#define HINIC_DMA_ATTR_ENTRY_SET(val, member)			\
		(((u32)(val) & HINIC_DMA_ATTR_ENTRY_##member##_MASK) << \
			HINIC_DMA_ATTR_ENTRY_##member##_SHIFT)

#define HINIC_DMA_ATTR_ENTRY_CLEAR(val, member)		\
		((val) & (~(HINIC_DMA_ATTR_ENTRY_##member##_MASK	\
			<< HINIC_DMA_ATTR_ENTRY_##member##_SHIFT)))

#define HINIC_PCIE_ST_DISABLE			0
#define HINIC_PCIE_AT_DISABLE			0
#define HINIC_PCIE_PH_DISABLE			0

#define PCIE_MSIX_ATTR_ENTRY			0

#define HINIC_MSG_TO_MGMT_MAX_LEN		2016

/**
 * hinic_cpu_to_be32 - convert data to big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert, must be Multiple of 4B
 **/
void hinic_cpu_to_be32(void *data, int len)
{
	u32 i;
	u32 *mem = (u32 *)data;

	for (i = 0; i < ((u32)len >> 2); i++) {
		*mem = cpu_to_be32(*mem);
		mem++;
	}
}

/**
 * hinic_cpu_to_be32 - convert data from big endian 32 bit format
 * @data: the data to convert
 * @len: length of data to convert
 **/
void hinic_be32_to_cpu(void *data, int len)
{
	int i, chunk_sz = sizeof(u32);
	u32 *mem = (u32 *)data;

	len = len / chunk_sz;

	for (i = 0; i < len; i++) {
		*mem = be32_to_cpu(*mem);
		mem++;
	}
}

/**
 * hinic_set_sge - set dma area in scatter gather entry
 * @sge: scatter gather entry
 * @addr: dma address
 * @len: length of relevant data in the dma address
 **/
void hinic_set_sge(struct hinic_sge *sge, dma_addr_t addr, u32 len)
{
	sge->hi_addr = upper_32_bits(addr);
	sge->lo_addr = lower_32_bits(addr);
	sge->len  = len;
}

/**
 * hinic_set_ci_table - set ci attribute table
 * @hwdev: the hardware interface of a nic device
 * @q_id: Queue id of SQ
 * @attr: Point to SQ CI attribute table
 * @return
 *   0 on success and ci attribute table is filled,
 *   negative error value otherwise.
 **/
int hinic_set_ci_table(void *hwdev, u16 q_id, struct hinic_sq_attr *attr)
{
	struct hinic_cons_idx_attr cons_idx_attr;

	memset(&cons_idx_attr, 0, sizeof(cons_idx_attr));
	cons_idx_attr.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	cons_idx_attr.func_idx = hinic_global_func_id(hwdev);
	cons_idx_attr.dma_attr_off  = attr->dma_attr_off;
	cons_idx_attr.pending_limit = attr->pending_limit;
	cons_idx_attr.coalescing_time = attr->coalescing_time;
	if (attr->intr_en) {
		cons_idx_attr.intr_en = attr->intr_en;
		cons_idx_attr.intr_idx = attr->intr_idx;
	}

	cons_idx_attr.l2nic_sqn = attr->l2nic_sqn;
	cons_idx_attr.sq_id = q_id;
	cons_idx_attr.ci_addr = attr->ci_dma_base;

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				      HINIC_MGMT_CMD_L2NIC_SQ_CI_ATTR_SET,
				      &cons_idx_attr, sizeof(cons_idx_attr),
				      NULL, NULL, 0);
}

/**
 * get_hw_rx_buf_size - translate rx_buf_size into hw_rx_buf_size
 * @rx_buf_sz: receive buffer size
 * @return
 *   hw rx buffer size
 **/
static u16 get_hw_rx_buf_size(int rx_buf_sz)
{
	u16 num_hw_types = sizeof(hinic_hw_rx_buf_size)
			   / sizeof(hinic_hw_rx_buf_size[0]);
	u16 i;

	for (i = 0; i < num_hw_types; i++) {
		if (hinic_hw_rx_buf_size[i] == rx_buf_sz)
			return i;
	}

	pr_err("Hw can't support rx buf size of %d\n", rx_buf_sz);

	return DEFAULT_RX_BUF_SIZE;	/* default 2K */
}

/**
 * hinic_set_pagesize - set page size to vat table
 * @hwdev: the hardware interface of a nic device
 * @page_size: vat page size
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_set_pagesize(void *hwdev, u8 page_size)
{
	struct hinic_page_size cmd;

	if (page_size > HINIC_PAGE_SIZE_MAX) {
		pr_err("Invalid page_size %u, bigger than %u\n",
		       page_size, HINIC_PAGE_SIZE_MAX);
		return -EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	cmd.func_idx = hinic_global_func_id(hwdev);
	cmd.ppf_idx = hinic_ppf_idx(hwdev);
	cmd.page_size = page_size;

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
					HINIC_MGMT_CMD_PAGESIZE_SET,
					&cmd, sizeof(cmd),
					NULL, NULL, 0);
}

/**
 * hinic_set_root_ctxt - init root context in NIC
 * @hwdev: the hardware interface of a nic device
 * @rq_depth: the depth of receive queue
 * @sq_depth: the depth of transmit queue
 * @rx_buf_sz: receive buffer size from app
 * Return: 0 on success, negative error value otherwise.
 **/
int hinic_set_root_ctxt(void *hwdev, u16 rq_depth, u16 sq_depth, int rx_buf_sz)
{
	struct hinic_root_ctxt root_ctxt;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	root_ctxt.func_idx = hinic_global_func_id(hwdev);
	root_ctxt.ppf_idx = hinic_ppf_idx(hwdev);
	root_ctxt.set_cmdq_depth = 0;
	root_ctxt.cmdq_depth = 0;
	root_ctxt.lro_en = 1;
	root_ctxt.rq_depth  = (u16)ilog2(rq_depth);
	root_ctxt.rx_buf_sz = get_hw_rx_buf_size(rx_buf_sz);
	root_ctxt.sq_depth  = (u16)ilog2(sq_depth);

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				      HINIC_MGMT_CMD_VAT_SET,
				      &root_ctxt, sizeof(root_ctxt),
				      NULL, NULL, 0);
}

/**
 * hinic_clean_root_ctxt - clean root context table in NIC
 * @hwdev: the hardware interface of a nic device
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_clean_root_ctxt(void *hwdev)
{
	struct hinic_root_ctxt root_ctxt;

	memset(&root_ctxt, 0, sizeof(root_ctxt));
	root_ctxt.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	root_ctxt.func_idx = hinic_global_func_id(hwdev);
	root_ctxt.ppf_idx = hinic_ppf_idx(hwdev);
	root_ctxt.set_cmdq_depth = 0;
	root_ctxt.cmdq_depth = 0;
	root_ctxt.lro_en = 0;
	root_ctxt.rq_depth  = 0;
	root_ctxt.rx_buf_sz = 0;
	root_ctxt.sq_depth  = 0;

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				      HINIC_MGMT_CMD_VAT_SET,
				      &root_ctxt, sizeof(root_ctxt),
				      NULL, NULL, 0);
}

static int wait_for_flr_finish(struct hinic_hwif *hwif)
{
	unsigned long end;
	enum hinic_pf_status status;

	end = jiffies + msecs_to_jiffies(HINIC_FLR_TIMEOUT);
	do {
		status = hinic_get_pf_status(hwif);
		if (status == HINIC_PF_STATUS_FLR_FINISH_FLAG) {
			hinic_set_pf_status(hwif, HINIC_PF_STATUS_ACTIVE_FLAG);
			return 0;
		}

		msleep(10);
	} while (time_before(jiffies, end));

	return -EFAULT;
}

#define HINIC_WAIT_CMDQ_IDLE_TIMEOUT		1000

static int wait_cmdq_stop(struct hinic_hwdev *hwdev)
{
	enum hinic_cmdq_type cmdq_type;
	struct hinic_cmdqs *cmdqs = hwdev->cmdqs;
	unsigned long end;
	int err = 0;

	if (!(cmdqs->status & HINIC_CMDQ_ENABLE))
		return 0;

	cmdqs->status &= ~HINIC_CMDQ_ENABLE;

	end = jiffies + msecs_to_jiffies(HINIC_WAIT_CMDQ_IDLE_TIMEOUT);
	do {
		err = 0;
		cmdq_type = HINIC_CMDQ_SYNC;
		for (; cmdq_type < HINIC_MAX_CMDQ_TYPES; cmdq_type++) {
			if (!hinic_cmdq_idle(&cmdqs->cmdq[cmdq_type])) {
				err = -EBUSY;
				break;
			}
		}

		if (!err)
			return 0;

		msleep(1);
	} while (time_before(jiffies, end));

	cmdqs->status |= HINIC_CMDQ_ENABLE;

	return err;
}

/**
 * hinic_pf_rx_tx_flush - clean up hardware resource
 * @hwdev: the hardware interface of a nic device
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
static int hinic_pf_rx_tx_flush(struct hinic_hwdev *hwdev)
{
	struct hinic_hwif *hwif = hwdev->hwif;
	struct hinic_clear_doorbell clear_db;
	struct hinic_clear_resource clr_res;
	int err;

	msleep(100);

	err = wait_cmdq_stop(hwdev);
	if (err) {
		dev_err(hwdev->dev_hdl, "Cmdq is still working\n");
		return err;
	}

	hinic_disable_doorbell(hwif);
	memset(&clear_db, 0, sizeof(clear_db));
	clear_db.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	clear_db.func_idx = HINIC_HWIF_GLOBAL_IDX(hwif);
	clear_db.ppf_idx  = HINIC_HWIF_PPF_IDX(hwif);
	err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_FLUSH_DOORBELL, &clear_db,
				     sizeof(clear_db), NULL, NULL, 0);
	if (err)
		dev_warn(hwdev->dev_hdl, "Flush doorbell failed\n");

	hinic_set_pf_status(hwif, HINIC_PF_STATUS_FLR_START_FLAG);
	memset(&clr_res, 0, sizeof(clr_res));
	clr_res.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	clr_res.func_idx = HINIC_HWIF_GLOBAL_IDX(hwif);
	clr_res.ppf_idx  = HINIC_HWIF_PPF_IDX(hwif);

	err = hinic_msg_to_mgmt_no_ack(hwdev, HINIC_MOD_COMM,
				       HINIC_MGMT_CMD_START_FLR, &clr_res,
				       sizeof(clr_res), NULL, NULL);
	if (err)
		dev_warn(hwdev->dev_hdl, "Notice flush message failed\n");

	err = wait_for_flr_finish(hwif);
	if (err)
		dev_warn(hwdev->dev_hdl, "Wait firmware FLR timeout\n");

	hinic_enable_doorbell(hwif);

	err = hinic_reinit_cmdq_ctxts(hwdev);
	if (err)
		dev_warn(hwdev->dev_hdl, "Reinit cmdq failed\n");

	return 0;
}

int hinic_func_rx_tx_flush(struct hinic_hwdev *hwdev)
{
	return hinic_pf_rx_tx_flush(hwdev);
}

/**
 * hinic_get_interrupt_cfg - get interrupt configuation from NIC
 * @hwdev: the hardware interface of a nic device
 * @interrupt_info: Information of Interrupt aggregation
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
static int hinic_get_interrupt_cfg(struct hinic_hwdev *hwdev,
				struct nic_interrupt_info *interrupt_info)
{
	struct hinic_msix_config msix_cfg;
	u16 out_size = sizeof(msix_cfg);
	int err;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	msix_cfg.func_id = hinic_global_func_id(hwdev);
	msix_cfg.msix_index = interrupt_info->msix_index;

	err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_MSI_CTRL_REG_RD_BY_UP,
				     &msix_cfg, sizeof(msix_cfg),
				     &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.mgmt_msg_head.status) {
		dev_err(hwdev->dev_hdl, "Get interrupt config failed, ret: %d\n",
			msix_cfg.mgmt_msg_head.status);
		return -EINVAL;
	}

	interrupt_info->lli_credit_limit = msix_cfg.lli_credit_cnt;
	interrupt_info->lli_timer_cfg = msix_cfg.lli_tmier_cnt;
	interrupt_info->pending_limt = msix_cfg.pending_cnt;
	interrupt_info->coalesc_timer_cfg = msix_cfg.coalesct_timer_cnt;
	interrupt_info->resend_timer_cfg = msix_cfg.resend_timer_cnt;
	return 0;
}

/**
 * hinic_set_interrupt_cfg - set interrupt configuation to NIC
 * @hwdev: the hardware interface of a nic device
 * @interrupt_info: Information of Interrupt aggregation
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_set_interrupt_cfg(struct hinic_hwdev *hwdev,
			    struct nic_interrupt_info interrupt_info)
{
	struct hinic_msix_config msix_cfg;
	struct nic_interrupt_info temp_info;
	u16 out_size = sizeof(msix_cfg);
	int err;

	memset(&msix_cfg, 0, sizeof(msix_cfg));
	msix_cfg.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	msix_cfg.func_id = hinic_global_func_id(hwdev);
	msix_cfg.msix_index = (u16)interrupt_info.msix_index;

	temp_info.msix_index = interrupt_info.msix_index;

	err = hinic_get_interrupt_cfg(hwdev, &temp_info);
	if (err)
		return -EINVAL;

	msix_cfg.lli_credit_cnt = temp_info.lli_credit_limit;
	msix_cfg.lli_tmier_cnt = temp_info.lli_timer_cfg;
	msix_cfg.pending_cnt = temp_info.pending_limt;
	msix_cfg.coalesct_timer_cnt = temp_info.coalesc_timer_cfg;
	msix_cfg.resend_timer_cnt = temp_info.resend_timer_cfg;

	if (interrupt_info.lli_set) {
		msix_cfg.lli_credit_cnt = interrupt_info.lli_credit_limit;
		msix_cfg.lli_tmier_cnt = interrupt_info.lli_timer_cfg;
	}

	if (interrupt_info.interrupt_coalesc_set) {
		msix_cfg.pending_cnt = interrupt_info.pending_limt;
		msix_cfg.coalesct_timer_cnt = interrupt_info.coalesc_timer_cfg;
		msix_cfg.resend_timer_cnt = interrupt_info.resend_timer_cfg;
	}

	err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_MSI_CTRL_REG_WR_BY_UP,
				     &msix_cfg, sizeof(msix_cfg),
				     &msix_cfg, &out_size, 0);
	if (err || !out_size || msix_cfg.mgmt_msg_head.status) {
		dev_err(hwdev->dev_hdl, "Set interrupt config failed, ret: %d\n",
			msix_cfg.mgmt_msg_head.status);
		return -EINVAL;
	}

	return 0;
}

/**
 * hinic_misx_intr_clear_resend_bit - clear interrupt resend configuration
 * @hwdev: the hardware interface of a nic device
 * @msix_idx: Index of msix interrupt
 * @clear_resend_en: enable flag of clear resend configuration
 **/
void hinic_misx_intr_clear_resend_bit(void *hwdev, u16 msix_idx,
				      u8 clear_resend_en)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;
	u32 msix_ctrl = 0, addr;

	msix_ctrl = HINIC_MSIX_CNT_SET(clear_resend_en, RESEND_TIMER);

	addr = HINIC_CSR_MSIX_CNT_ADDR(msix_idx);

	hinic_hwif_write_reg(hwif, addr, msix_ctrl);
}

/**
 * init_aeqs_msix_attr - Init interrupt attributes of aeq
 * @hwdev: the hardware interface of a nic device
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int init_aeqs_msix_attr(void *hwdev)
{
	struct hinic_hwdev *nic_hwdev = (struct hinic_hwdev *)hwdev;
	struct hinic_aeqs *aeqs = nic_hwdev->aeqs;
	struct nic_interrupt_info info = {0};
	struct hinic_eq *eq;
	u16 q_id;
	int err;

	info.lli_set = 0;
	info.interrupt_coalesc_set = 1;
	info.pending_limt = HINIC_DEAULT_EQ_MSIX_PENDING_LIMIT;
	info.coalesc_timer_cfg = HINIC_DEAULT_EQ_MSIX_COALESC_TIMER_CFG;
	info.resend_timer_cfg = HINIC_DEAULT_EQ_MSIX_RESEND_TIMER_CFG;

	for (q_id = 0; q_id < aeqs->num_aeqs; q_id++) {
		eq = &aeqs->aeq[q_id];
		info.msix_index = eq->eq_irq.msix_entry_idx;
		err = hinic_set_interrupt_cfg(hwdev, info);
		if (err) {
			dev_err(nic_hwdev->dev_hdl,
				"Set msix attr for aeq %d failed\n", q_id);
			return -EFAULT;
		}
	}

	return 0;
}

/**
 * set_pf_dma_attr_entry - set the dma attributes for entry
 * @hwdev: the pointer to the private hardware device object
 * @entry_idx: the entry index in the dma table
 * @st: PCIE TLP steering tag
 * @at:	PCIE TLP AT field
 * @ph: PCIE TLP Processing Hint field
 * @no_snooping: PCIE TLP No snooping
 * @tph_en: PCIE TLP Processing Hint Enable
 **/
static void set_pf_dma_attr_entry(struct hinic_hwdev *hwdev, u32 entry_idx,
				  u8 st, u8 at, u8 ph,
				  enum hinic_pcie_nosnoop no_snooping,
				  enum hinic_pcie_tph tph_en)
{
	u32 addr, val, dma_attr_entry;

	/* Read Modify Write */
	addr = HINIC_CSR_DMA_ATTR_TBL_ADDR(entry_idx);

	val = hinic_hwif_read_reg(hwdev->hwif, addr);
	val = HINIC_DMA_ATTR_ENTRY_CLEAR(val, ST)	&
		HINIC_DMA_ATTR_ENTRY_CLEAR(val, AT)	&
		HINIC_DMA_ATTR_ENTRY_CLEAR(val, PH)	&
		HINIC_DMA_ATTR_ENTRY_CLEAR(val, NO_SNOOPING)	&
		HINIC_DMA_ATTR_ENTRY_CLEAR(val, TPH_EN);

	dma_attr_entry = HINIC_DMA_ATTR_ENTRY_SET(st, ST)	|
			 HINIC_DMA_ATTR_ENTRY_SET(at, AT)	|
			 HINIC_DMA_ATTR_ENTRY_SET(ph, PH)	|
			 HINIC_DMA_ATTR_ENTRY_SET(no_snooping, NO_SNOOPING) |
			 HINIC_DMA_ATTR_ENTRY_SET(tph_en, TPH_EN);

	val |= dma_attr_entry;
	hinic_hwif_write_reg(hwdev->hwif, addr, val);
}

/**
 * dma_attr_table_init - initialize the the default dma attributes
 * @hwdev: the pointer to the private hardware device object
 **/
static void dma_attr_table_init(struct hinic_hwdev *hwdev)
{
	if (HINIC_IS_VF(hwdev))
		return;

	set_pf_dma_attr_entry(hwdev, PCIE_MSIX_ATTR_ENTRY,
			      HINIC_PCIE_ST_DISABLE,
			      HINIC_PCIE_AT_DISABLE,
			      HINIC_PCIE_PH_DISABLE,
			      HINIC_PCIE_SNOOP,
			      HINIC_PCIE_TPH_DISABLE);
}

int hinic_init_attr_table(struct hinic_hwdev *hwdev)
{
	int rc;

	dma_attr_table_init(hwdev);

	rc = init_aeqs_msix_attr(hwdev);
	HINIC_ERR_RET(hwdev->dev_hdl, HINIC_OK != rc, rc,
		      "Init aeqs_msix_attr failed");

	return HINIC_OK;
}

static int hinic_get_mgmt_channel_status(void *handle)
{
	struct hinic_hwdev *hwdev = (struct hinic_hwdev *)handle;
	u32 val;

	if (!hwdev)
		return true;

	val = hinic_hwif_read_reg(hwdev->hwif, HINIC_ICPL_RESERVD_ADDR);

	return HINIC_GET_MGMT_CHANNEL_STATUS(val, MGMT_CHANNEL_STATUS);
}

int hinic_msg_to_mgmt_sync(void *hwdev, enum hinic_mod_type mod, u8 cmd,
			   void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size, u32 timeout)
{
	int rc = HINIC_ERROR;

	if (!hwdev || in_size > HINIC_MSG_TO_MGMT_MAX_LEN)
		return -EINVAL;

	/* If status is hot upgrading, don't send message to mgmt */
	if (hinic_get_mgmt_channel_status(hwdev))
		return -EPERM;

	rc = hinic_pf_to_mgmt_sync(hwdev, mod, cmd, buf_in,
				   in_size, buf_out, out_size,
				   timeout);

	return rc;
}

#define FAULT_SHOW_STR_LEN 16
static void fault_report_show(struct hinic_hwdev *hwdev,
			      struct hinic_fault_event *event)
{
	char fault_type[FAULT_TYPE_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"chip", "ucode", "mem rd timeout", "mem wr timeout",
		"reg rd timeout", "reg wr timeout"};
	char fault_level[FAULT_LEVEL_MAX][FAULT_SHOW_STR_LEN + 1] = {
		"fatal", "reset", "flr", "general", "suggestion"};
	char type_str[FAULT_SHOW_STR_LEN + 1] = { 0 };
	char level_str[FAULT_SHOW_STR_LEN + 1] = { 0 };
	u8 err_level;

	dev_warn(hwdev->dev_hdl, "Fault event report received, func_id: %d\n",
		 hinic_global_func_id(hwdev));

	if (event->type < FAULT_TYPE_MAX)
		strncpy(type_str, fault_type[event->type], FAULT_SHOW_STR_LEN);
	else
		strncpy(type_str, "unknown", FAULT_SHOW_STR_LEN);
	dev_warn(hwdev->dev_hdl, "fault type:    %d [%s]\n",
		 event->type, type_str);
	dev_warn(hwdev->dev_hdl, "fault val[0]:  0x%08x\n",
		 event->event.val[0]);
	dev_warn(hwdev->dev_hdl, "fault val[1]:  0x%08x\n",
		 event->event.val[1]);
	dev_warn(hwdev->dev_hdl, "fault val[2]:  0x%08x\n",
		 event->event.val[2]);
	dev_warn(hwdev->dev_hdl, "fault val[3]:  0x%08x\n",
		 event->event.val[3]);

	switch (event->type) {
	case FAULT_TYPE_CHIP:
		err_level = event->event.chip.err_level;
		if (err_level < FAULT_LEVEL_MAX)
			strncpy(level_str, fault_level[err_level],
				FAULT_SHOW_STR_LEN);
		else
			strncpy(level_str, "unknown",
				FAULT_SHOW_STR_LEN);

		dev_warn(hwdev->dev_hdl, "err_level:     %d [%s]\n",
			 err_level, level_str);

		if (err_level == FAULT_LEVEL_SERIOUS_FLR) {
			dev_warn(hwdev->dev_hdl, "flr func_id:   %d\n",
				 event->event.chip.func_id);
		} else {
			dev_warn(hwdev->dev_hdl, "node_id:       %d\n",
				 event->event.chip.node_id);
			dev_warn(hwdev->dev_hdl, "err_type:      %d\n",
				 event->event.chip.err_type);
			dev_warn(hwdev->dev_hdl, "err_csr_addr:  %d\n",
				 event->event.chip.err_csr_addr);
			dev_warn(hwdev->dev_hdl, "err_csr_value: %d\n",
				 event->event.chip.err_csr_value);
		}
		break;
	case FAULT_TYPE_UCODE:
		dev_warn(hwdev->dev_hdl, "cause_id:      %d\n",
			 event->event.ucode.cause_id);
		dev_warn(hwdev->dev_hdl, "core_id:       %d\n",
			 event->event.ucode.core_id);
		dev_warn(hwdev->dev_hdl, "c_id:          %d\n",
			 event->event.ucode.c_id);
		dev_warn(hwdev->dev_hdl, "epc:           %d\n",
			 event->event.ucode.epc);
		break;
	case FAULT_TYPE_MEM_RD_TIMEOUT:
	case FAULT_TYPE_MEM_WR_TIMEOUT:
		dev_warn(hwdev->dev_hdl, "err_csr_ctrl:  %d\n",
			 event->event.mem_timeout.err_csr_ctrl);
		dev_warn(hwdev->dev_hdl, "err_csr_data:  %d\n",
			 event->event.mem_timeout.err_csr_data);
		dev_warn(hwdev->dev_hdl, "ctrl_tab:      %d\n",
			 event->event.mem_timeout.ctrl_tab);
		dev_warn(hwdev->dev_hdl, "mem_index:     %d\n",
			 event->event.mem_timeout.mem_index);
		break;
	case FAULT_TYPE_REG_RD_TIMEOUT:
	case FAULT_TYPE_REG_WR_TIMEOUT:
		dev_warn(hwdev->dev_hdl, "err_csr:       %d\n",
			 event->event.reg_timeout.err_csr);
		break;
	default:
		break;
	}
}

static int resources_state_set(struct hinic_hwdev *hwdev,
			       enum hinic_res_state state)
{
	struct hinic_hwif *hwif = hwdev->hwif;
	struct hinic_cmd_set_res_state res_state;

	memset(&res_state, 0, sizeof(res_state));
	res_state.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	res_state.func_idx = HINIC_HWIF_GLOBAL_IDX(hwif);
	res_state.state = state;

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				 HINIC_MGMT_CMD_RES_STATE_SET,
				 &res_state, sizeof(res_state), NULL, NULL, 0);
}

/**
 * hinic_activate_hwdev_state - Active host nic state and notify mgmt channel
 * that host nic is ready.
 * @hwdev: the hardware interface of a nic device
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_activate_hwdev_state(struct hinic_hwdev *hwdev)
{
	int rc = HINIC_OK;

	if (!hwdev)
		return -EINVAL;

	if (!HINIC_IS_VF(hwdev))
		hinic_set_pf_status(hwdev->hwif,
				    HINIC_PF_STATUS_ACTIVE_FLAG);

	rc = resources_state_set(hwdev, HINIC_RES_ACTIVE);
	HINIC_ERR_RET(hwdev->dev_hdl, HINIC_OK != rc, rc,
		      "Init resources_state failed");

	return rc;
}

/**
 * hinic_deactivate_hwdev_state - Deactivate host nic state and notify mgmt
 * channel that host nic is not ready.
 * @hwdev: the pointer to the private hardware device object
 **/
void hinic_deactivate_hwdev_state(struct hinic_hwdev *hwdev)
{
	int rc = HINIC_OK;

	if (!hwdev)
		return;

	rc = resources_state_set(hwdev, HINIC_RES_CLEAN);
	if (rc != HINIC_OK)
		HINIC_PRINT_ERR("Deinit resources state failed");

	if (!HINIC_IS_VF(hwdev))
		hinic_set_pf_status(hwdev->hwif, HINIC_PF_STATUS_INIT);
}

int hinic_get_board_info(void *hwdev, struct hinic_board_info *info)
{
	struct hinic_comm_board_info board_info;
	u16 out_size = sizeof(board_info);
	int err;

	if (!hwdev || !info)
		return -EINVAL;

	memset(&board_info, 0, sizeof(board_info));
	board_info.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_GET_BOARD_INFO,
				     &board_info, sizeof(board_info),
				     &board_info, &out_size, 0);
	if (err || board_info.mgmt_msg_head.status || !out_size) {
		dev_err(((struct hinic_hwdev *)hwdev)->dev_hdl,
			"Failed to get board info, err: %d, status: 0x%x, out size: 0x%x\n",
			err, board_info.mgmt_msg_head.status, out_size);
		return -EFAULT;
	}

	memcpy(info, &board_info.info, sizeof(*info));
	return 0;
}

/**
 * hinic_l2nic_reset - Restore the initial state of NIC
 * @hwdev: the hardware interface of a nic device
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_l2nic_reset(struct hinic_hwdev *hwdev)
{
	struct hinic_hwif *hwif = hwdev->hwif;
	struct hinic_l2nic_reset l2nic_reset;
	int err = 0;

	err = hinic_set_vport_enable(hwdev, false);
	if (err) {
		dev_err(hwdev->dev_hdl, "Set vport disable failed\n");
		return err;
	}

	msleep(100);

	memset(&l2nic_reset, 0, sizeof(l2nic_reset));
	l2nic_reset.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	l2nic_reset.func_id = HINIC_HWIF_GLOBAL_IDX(hwif);
	err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_L2NIC_RESET,
				     &l2nic_reset, sizeof(l2nic_reset),
				     NULL, NULL, 0);
	if (err || l2nic_reset.mgmt_msg_head.status) {
		dev_err(hwdev->dev_hdl, "Reset L2NIC resources failed\n");
		return -EFAULT;
	}

	return 0;
}

static void hinic_show_sw_watchdog_timeout_info(struct hinic_hwdev *hwdev,
						void *buf_in, u16 in_size,
						void *buf_out, u16 *out_size)
{
	struct hinic_mgmt_watchdog_info *watchdog_info;
	u32 *dump_addr, *reg, stack_len, i, j;

	if (in_size != sizeof(*watchdog_info)) {
		dev_err(hwdev->dev_hdl, "Invalid mgmt watchdog report, length: %d, should be %ld\n",
			in_size, sizeof(*watchdog_info));
		return;
	}

	watchdog_info = (struct hinic_mgmt_watchdog_info *)buf_in;

	dev_err(hwdev->dev_hdl, "Mgmt deadloop time: 0x%x 0x%x, task id: 0x%x, sp: 0x%x\n",
		watchdog_info->curr_time_h, watchdog_info->curr_time_l,
		watchdog_info->task_id, watchdog_info->sp);
	dev_err(hwdev->dev_hdl, "Stack current used: 0x%x, peak used: 0x%x, overflow flag: 0x%x, top: 0x%x, bottom: 0x%x\n",
		watchdog_info->curr_used, watchdog_info->peak_used,
		watchdog_info->is_overflow, watchdog_info->stack_top,
		watchdog_info->stack_bottom);

	dev_err(hwdev->dev_hdl, "Mgmt pc: 0x%08x, lr: 0x%08x, cpsr:0x%08x\n",
		watchdog_info->pc, watchdog_info->lr, watchdog_info->cpsr);

	dev_err(hwdev->dev_hdl, "Mgmt register info\n");

	for (i = 0; i < 3; i++) {
		reg = watchdog_info->reg + (u64)(u32)(4 * i);
		dev_err(hwdev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*(reg), *(reg + 1), *(reg + 2), *(reg + 3));
	}

	dev_err(hwdev->dev_hdl, "0x%08x\n", watchdog_info->reg[12]);

	if (watchdog_info->stack_actlen <= 1024) {
		stack_len = watchdog_info->stack_actlen;
	} else {
		dev_err(hwdev->dev_hdl, "Oops stack length: 0x%x is wrong\n",
			watchdog_info->stack_actlen);
		stack_len = 1024;
	}

	dev_err(hwdev->dev_hdl, "Mgmt dump stack, 16Bytes per line(start from sp)\n");
	for (i = 0; i < (stack_len / 16); i++) {
		dump_addr = (u32 *)(watchdog_info->data + ((u64)(u32)(i * 16)));
		dev_err(hwdev->dev_hdl, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			*dump_addr, *(dump_addr + 1), *(dump_addr + 2),
			*(dump_addr + 3));
	}

	for (j = 0; j < ((stack_len % 16) / 4); j++) {
		dump_addr = (u32 *)(watchdog_info->data +
			    ((u64)(u32)(i * 16 + j * 4)));
		dev_err(hwdev->dev_hdl, "0x%08x ", *dump_addr);
	}

	*out_size = sizeof(*watchdog_info);
	watchdog_info = (struct hinic_mgmt_watchdog_info *)buf_out;
	watchdog_info->mgmt_msg_head.status = 0;

	return;
}

static void hinic_show_pcie_dfx_info(struct hinic_hwdev *hwdev,
				     void *buf_in, u16 in_size,
				     void *buf_out, u16 *out_size)
{
	struct hinic_pcie_dfx_ntc *notice_info =
		(struct hinic_pcie_dfx_ntc *)buf_in;
	struct hinic_pcie_dfx_info dfx_info;
	u16 size = 0;
	u16 cnt = 0;
	u32 num = 0;
	u32 i, j;
	int err;
	u32 *reg;

	if (in_size != sizeof(*notice_info)) {
		dev_err(hwdev->dev_hdl, "Invalid pcie dfx notice info, length: %d, should be %ld.\n",
			in_size, sizeof(*notice_info));
		return;
	}

	((struct hinic_pcie_dfx_ntc *)buf_out)->mgmt_msg_head.status = 0;
	*out_size = sizeof(*notice_info);
	memset(&dfx_info, 0, sizeof(dfx_info));
	num = (u32)(notice_info->len / 1024);
	dev_info(hwdev->dev_hdl, "INFO LEN: %d\n", notice_info->len);
	dev_info(hwdev->dev_hdl, "PCIE DFX:\n");
	dfx_info.host_id = 0;
	dfx_info.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	for (i = 0; i < num; i++) {
		dfx_info.offset = i * MAX_PCIE_DFX_BUF_SIZE;
		if (i == (num - 1))
			dfx_info.last = 1;
		size = sizeof(dfx_info);
		err = hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
					     HINIC_MGMT_CMD_PCIE_DFX_GET,
					     &dfx_info, sizeof(dfx_info),
					     &dfx_info, &size, 0);
		if (err || dfx_info.mgmt_msg_head.status || !size) {
			dev_err(((struct hinic_hwdev *)hwdev)->dev_hdl,
				"Failed to get pcie dfx info, err: %d, status: 0x%x, out size: 0x%x\n",
				err, dfx_info.mgmt_msg_head.status, size);
			return;
		}

		reg = (u32 *)dfx_info.data;
		for (j = 0; j < 256; j = j + 8) {
			dev_err(hwdev->dev_hdl, "0x%04x: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
				cnt, reg[j], reg[(u32)(j + 1)],
				reg[(u32)(j + 2)], reg[(u32)(j + 3)],
				reg[(u32)(j + 4)], reg[(u32)(j + 5)],
				reg[(u32)(j + 6)], reg[(u32)(j + 7)]);
			cnt = cnt + 32;
		}
		memset(dfx_info.data, 0, MAX_PCIE_DFX_BUF_SIZE);
	}
}

static void
hinic_show_ffm_info(struct hinic_hwdev *hwdev, void *buf_in, u16 in_size,
			void *buf_out, u16 *out_size)
{
	struct ffm_intr_info *intr;
	hinic_nic_dev *nic_dev = (hinic_nic_dev *)hwdev->dev_hdl;

	if (in_size != sizeof(struct ffm_intr_info)) {
		dev_err(hwdev->dev_hdl, "Invalid input buffer len, length: %d, should be %ld.\n",
			in_size, sizeof(struct ffm_intr_info));
		return;
	}

	if (nic_dev->ffm_num < FFM_RECORD_NUM_MAX) {
		nic_dev->ffm_num++;
		intr = (struct ffm_intr_info *)buf_in;
		dev_warning(hwdev->dev_hdl, "node_id(%d),err_csr_addr(0x%x),err_csr_val(0x%x),err_level(0x%x),err_type(0x%x)\n",
			    intr->node_id,
			    intr->err_csr_addr,
			    intr->err_csr_value,
			    intr->err_level,
			    intr->err_type);
	}
}

void hinic_comm_async_event_handle(struct hinic_hwdev *hwdev, u8 cmd,
				   void *buf_in, u16 in_size,
				   void *buf_out, u16 *out_size)
{
	struct hinic_cmd_fault_event *fault_event, *ret_fault_event;

	if (!hwdev)
		return;

	*out_size = 0;

	switch (cmd) {
	case HINIC_MGMT_CMD_FAULT_REPORT:
		if (in_size != sizeof(*fault_event)) {
			dev_err(hwdev->dev_hdl, "Invalid fault event report, length: %d, should be %ld\n",
				in_size, sizeof(*fault_event));
			return;
		}

		fault_event = (struct hinic_cmd_fault_event *)buf_in;
		fault_report_show(hwdev, &fault_event->event);

		if (hinic_func_type(hwdev) != TYPE_VF) {
			ret_fault_event =
				(struct hinic_cmd_fault_event *)buf_out;
			ret_fault_event->mgmt_msg_head.status = 0;
			*out_size = sizeof(*ret_fault_event);
		}
		break;

	case HINIC_MGMT_CMD_WATCHDOG_INFO:
		hinic_show_sw_watchdog_timeout_info(hwdev, buf_in, in_size,
						    buf_out, out_size);
		break;

	case HINIC_MGMT_CMD_PCIE_DFX_NTC:
		hinic_show_pcie_dfx_info(hwdev, buf_in, in_size,
					 buf_out, out_size);
		break;

	case HINIC_MGMT_CMD_FFM_SET:
		hinic_show_ffm_info(hwdev, buf_in, in_size, buf_out, out_size);
		break;

	default:
		dev_warning(hwdev->dev_hdl, "Unsupported event %d to process\n",
			    cmd);

		break;
	}
}

static void hinic_cable_status_event(struct hinic_hwdev *hwdev, u8 cmd,
				     void *buf_in, u16 in_size, void *buf_out,
				     u16 *out_size)
{
	struct hinic_cable_plug_event *plug_event;
	struct hinic_link_err_event *link_err;

	if (cmd == HINIC_PORT_CMD_CABLE_PLUG_EVENT) {
		plug_event = (struct hinic_cable_plug_event *)buf_in;
		dev_info(hwdev->dev_hdl, "Port module event: Cable %s\n",
			 plug_event->plugged ? "plugged" : "unplugged");

		*out_size = sizeof(*plug_event);
		plug_event = (struct hinic_cable_plug_event *)buf_out;
		plug_event->mgmt_msg_head.status = 0;
	} else if (cmd == HINIC_PORT_CMD_LINK_ERR_EVENT) {
		link_err = (struct hinic_link_err_event *)buf_in;
		if (link_err->err_type >= LINK_ERR_NUM) {
			dev_err(hwdev->dev_hdl, "Link failed, Unknown type: 0x%x\n",
				link_err->err_type);
		} else {
			dev_info(hwdev->dev_hdl, "Link failed, type: 0x%x: %s\n",
				 link_err->err_type,
				 hinic_module_link_err[link_err->err_type]);
		}

		*out_size = sizeof(*link_err);
		link_err = (struct hinic_link_err_event *)buf_out;
		link_err->mgmt_msg_head.status = 0;
	}
}

void hinic_l2nic_async_event_handle(struct hinic_hwdev *hwdev,
				    void *param, u8 cmd,
				    void *buf_in, u16 in_size,
				    void *buf_out, u16 *out_size)
{
	struct hinic_port_link_status *in_link, *out_link;
	struct rte_eth_dev *eth_dev;

	if (!hwdev)
		return;

	*out_size = 0;

	switch (cmd) {
	case HINIC_PORT_CMD_LINK_STATUS_REPORT:
		eth_dev = (struct rte_eth_dev *)param;
		in_link = (struct hinic_port_link_status *)buf_in;
		dev_info(hwdev->dev_hdl, "Link status event report, dev_name: %s, port_id: %d, link_status: %s\n",
			 eth_dev->data->name, eth_dev->data->port_id,
			 in_link->link ? "UP" : "DOWN");

		hinic_lsc_process(eth_dev, in_link->link);
		break;

	case HINIC_PORT_CMD_CABLE_PLUG_EVENT:
	case HINIC_PORT_CMD_LINK_ERR_EVENT:
		hinic_cable_status_event(hwdev, cmd, buf_in, in_size,
					 buf_out, out_size);
		break;

	case HINIC_PORT_CMD_MGMT_RESET:
		dev_warn(hwdev->dev_hdl, "Mgmt is reset\n");
		break;

	default:
		dev_err(hwdev->dev_hdl, "Unsupported event %d to process\n",
			cmd);
		break;
	}
}

static void print_cable_info(struct hinic_hwdev *hwdev,
			     struct hinic_link_info *info)
{
	char tmp_str[512] = {0};
	char tmp_vendor[17] = {0};
	const char *port_type = "Unknown port type";
	int i;

	if (info->cable_absent) {
		dev_info(hwdev->dev_hdl, "Cable unpresent\n");
		return;
	}

	if (info->port_type < LINK_PORT_MAX_TYPE)
		port_type = __hw_to_char_port_type[info->port_type];
	else
		dev_info(hwdev->dev_hdl, "Unknown port type: %u\n",
			 info->port_type);
	if (info->port_type == LINK_PORT_FIBRE) {
		if (info->port_sub_type == FIBRE_SUBTYPE_SR)
			port_type = "Fibre-SR";
		else if (info->port_sub_type == FIBRE_SUBTYPE_LR)
			port_type = "Fibre-LR";
	}

	for (i = sizeof(info->vendor_name) - 1; i >= 0; i--) {
		if (info->vendor_name[i] == ' ')
			info->vendor_name[i] = '\0';
		else
			break;
	}

	memcpy(tmp_vendor, info->vendor_name, sizeof(info->vendor_name));
	snprintf(tmp_str, (sizeof(tmp_str) - 1),
		 "Vendor: %s, %s, %s, length: %um, max_speed: %uGbps",
		 tmp_vendor, info->sfp_type ? "SFP" : "QSFP", port_type,
		 info->cable_length, info->cable_max_speed);
	if (info->port_type != LINK_PORT_COPPER)
		snprintf(tmp_str, (sizeof(tmp_str) - 1),
			 "%s, Temperature: %u", tmp_str,
			 info->cable_temp);

	dev_info(hwdev->dev_hdl, "Cable information: %s\n", tmp_str);
}

static void print_hi30_status(struct hinic_hwdev *hwdev,
			      struct hinic_link_info *info)
{
	struct hi30_ffe_data *ffe_data;
	struct hi30_ctle_data *ctle_data;

	ffe_data = (struct hi30_ffe_data *)info->hi30_ffe;
	ctle_data = (struct hi30_ctle_data *)info->hi30_ctle;

	dev_info(hwdev->dev_hdl, "TX_FFE: PRE2=%s%d; PRE1=%s%d; MAIN=%d; POST1=%s%d; POST1X=%s%d\n",
		 (ffe_data->PRE1 & 0x10) ? "-" : "",
		 (int)(ffe_data->PRE1 & 0xf),
		 (ffe_data->PRE2 & 0x10) ? "-" : "",
		 (int)(ffe_data->PRE2 & 0xf),
		 (int)ffe_data->MAIN,
		 (ffe_data->POST1 & 0x10) ? "-" : "",
		 (int)(ffe_data->POST1 & 0xf),
		 (ffe_data->POST2 & 0x10) ? "-" : "",
		 (int)(ffe_data->POST2 & 0xf));
	dev_info(hwdev->dev_hdl, "RX_CTLE: Gain1~3=%u %u %u; Boost1~3=%u %u %u; Zero1~3=%u %u %u; Squelch1~3=%u %u %u\n",
		 ctle_data->ctlebst[0], ctle_data->ctlebst[1],
		 ctle_data->ctlebst[2], ctle_data->ctlecmband[0],
		 ctle_data->ctlecmband[1], ctle_data->ctlecmband[2],
		 ctle_data->ctlermband[0], ctle_data->ctlermband[1],
		 ctle_data->ctlermband[2], ctle_data->ctleza[0],
		 ctle_data->ctleza[1], ctle_data->ctleza[2]);
}

static void print_link_info(struct hinic_hwdev *hwdev,
			    struct hinic_link_info *info,
			    enum hilink_info_print_event type)
{
	const char *fec = "None";

	if (info->fec < HILINK_FEC_MAX_TYPE)
		fec = __hw_to_char_fec[info->fec];
	else
		dev_info(hwdev->dev_hdl, "Unknown fec type: %u\n",
			 info->fec);

	if (type == HILINK_EVENT_LINK_UP || !info->an_state) {
		dev_info(hwdev->dev_hdl, "Link information: speed %dGbps, %s, autoneg %s\n",
			 info->speed, fec, info->an_state ? "on" : "off");
	} else {
		dev_info(hwdev->dev_hdl, "Link information: antoneg: %s\n",
			 info->an_state ? "on" : "off");
	}
}

static const char *hilink_info_report_type[HILINK_EVENT_MAX_TYPE] = {
	"", "link up", "link down", "cable plugged"
};

static void hinic_print_hilink_info(struct hinic_hwdev *hwdev, void *buf_in,
				    u16 in_size, void *buf_out, u16 *out_size)
{
	struct hinic_hilink_link_info *hilink_info =
		(struct hinic_hilink_link_info *)buf_in;
	struct hinic_link_info *info;
	enum hilink_info_print_event type;

	if (in_size != sizeof(*hilink_info)) {
		dev_err(hwdev->dev_hdl, "Invalid hilink info message size %d, should be %ld\n",
			in_size, sizeof(*hilink_info));
		return;
	}

	((struct hinic_hilink_link_info *)buf_out)->mgmt_msg_head.status = 0;
	*out_size = sizeof(*hilink_info);

	info = &hilink_info->info;
	type = hilink_info->info_type;

	if (type < HILINK_EVENT_LINK_UP || type >= HILINK_EVENT_MAX_TYPE) {
		dev_info(hwdev->dev_hdl, "Invalid hilink info report, type: %d\n",
			 type);
		return;
	}

	dev_info(hwdev->dev_hdl, "Hilink info report after %s\n",
		 hilink_info_report_type[type]);

	print_cable_info(hwdev, info);

	print_link_info(hwdev, info, type);

	print_hi30_status(hwdev, info);

	if (type == HILINK_EVENT_LINK_UP)
		return;

	if (type == HILINK_EVENT_CABLE_PLUGGED) {
		dev_info(hwdev->dev_hdl, "alos: %u, rx_los: %u\n",
			 info->alos, info->rx_los);
		return;
	}

	dev_info(hwdev->dev_hdl, "PMA ctrl: %s, MAC tx %s, MAC rx %s, PMA debug inforeg: 0x%x, PMA signal ok reg: 0x%x, RF/LF status reg: 0x%x\n",
		 info->pma_status ? "on" : "off",
		 info->mac_tx_en ? "enable" : "disable",
		 info->mac_rx_en ? "enable" : "disable", info->pma_dbg_info_reg,
		 info->pma_signal_ok_reg, info->rf_lf_status_reg);
	dev_info(hwdev->dev_hdl, "alos: %u, rx_los: %u, PCS block counter reg: 0x%x,PCS link: 0x%x, MAC link: 0x%x PCS_err_cnt: 0x%x\n",
		 info->alos, info->rx_los, info->pcs_err_blk_cnt_reg,
		 info->pcs_link_reg, info->mac_link_reg, info->pcs_err_cnt);
}

void hinic_hilink_async_event_handle(struct hinic_hwdev *hwdev, u8 cmd,
				     void *buf_in, u16 in_size,
				     void *buf_out, u16 *out_size)
{
	if (!hwdev)
		return;

	*out_size = 0;

	switch (cmd) {
	case HINIC_HILINK_CMD_GET_LINK_INFO:
		hinic_print_hilink_info(hwdev, buf_in, in_size, buf_out,
					out_size);
		break;

	default:
		dev_err(hwdev->dev_hdl, "Unsupported event %d to process\n",
			cmd);
		break;
	}
}

/**
 * hinic_convert_rx_buf_size - convert rx buffer size to hw size
 * @rx_buf_sz: receive buffer size of mbuf
 * @match_sz: receive buffer size of hardware
 * @return
 *   0 on success,
 *   negative error value otherwise.
 **/
int hinic_convert_rx_buf_size(u32 rx_buf_sz, u32 *match_sz)
{
	u32 i, num_hw_types, best_match_sz;

	if (unlikely(!match_sz || rx_buf_sz < HINIC_RX_BUF_SIZE_32B))
		return -EINVAL;

	if (rx_buf_sz >= HINIC_RX_BUF_SIZE_16K) {
		best_match_sz =  HINIC_RX_BUF_SIZE_16K;
		goto size_matched;
	}

	num_hw_types = sizeof(hinic_hw_rx_buf_size) /
		sizeof(hinic_hw_rx_buf_size[0]);
	best_match_sz = hinic_hw_rx_buf_size[0];
	for (i = 0; i < num_hw_types; i++) {
		if (rx_buf_sz == hinic_hw_rx_buf_size[i]) {
			best_match_sz = hinic_hw_rx_buf_size[i];
			break;
		} else if (rx_buf_sz < hinic_hw_rx_buf_size[i]) {
			break;
		} else {
			best_match_sz = hinic_hw_rx_buf_size[i];
		}
	}

size_matched:
	*match_sz = best_match_sz;

	return 0;
}
