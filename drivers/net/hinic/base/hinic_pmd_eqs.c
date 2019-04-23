/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"

#define AEQ_CTRL_0_INTR_IDX_SHIFT		0
#define AEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define AEQ_CTRL_0_PCI_INTF_IDX_SHIFT		20
#define AEQ_CTRL_0_INTR_MODE_SHIFT		31

#define AEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define AEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define AEQ_CTRL_0_PCI_INTF_IDX_MASK		0x3U
#define AEQ_CTRL_0_INTR_MODE_MASK		0x1U

#define AEQ_CTRL_0_SET(val, member)		\
				(((val) & AEQ_CTRL_0_##member##_MASK) << \
				AEQ_CTRL_0_##member##_SHIFT)

#define AEQ_CTRL_0_CLEAR(val, member)		\
				((val) & (~(AEQ_CTRL_0_##member##_MASK \
					<< AEQ_CTRL_0_##member##_SHIFT)))

#define AEQ_CTRL_1_LEN_SHIFT			0
#define AEQ_CTRL_1_ELEM_SIZE_SHIFT		24
#define AEQ_CTRL_1_PAGE_SIZE_SHIFT		28

#define AEQ_CTRL_1_LEN_MASK			0x1FFFFFU
#define AEQ_CTRL_1_ELEM_SIZE_MASK		0x3U
#define AEQ_CTRL_1_PAGE_SIZE_MASK		0xFU

#define AEQ_CTRL_1_SET(val, member)		\
				(((val) & AEQ_CTRL_1_##member##_MASK) << \
				AEQ_CTRL_1_##member##_SHIFT)

#define AEQ_CTRL_1_CLEAR(val, member)		\
				((val) & (~(AEQ_CTRL_1_##member##_MASK \
					<< AEQ_CTRL_1_##member##_SHIFT)))

#define CEQ_CTRL_0_INTR_IDX_SHIFT		0
#define CEQ_CTRL_0_DMA_ATTR_SHIFT		12
#define CEQ_CTRL_0_LIMIT_KICK_SHIFT		20
#define CEQ_CTRL_0_PCI_INTF_IDX_SHIFT		24
#define CEQ_CTRL_0_INTR_MODE_SHIFT		31

#define CEQ_CTRL_0_INTR_IDX_MASK		0x3FFU
#define CEQ_CTRL_0_DMA_ATTR_MASK		0x3FU
#define CEQ_CTRL_0_LIMIT_KICK_MASK		0xFU
#define CEQ_CTRL_0_PCI_INTF_IDX_MASK		0x3U
#define CEQ_CTRL_0_INTR_MODE_MASK		0x1U

#define CEQ_CTRL_0_SET(val, member)		\
				(((val) & CEQ_CTRL_0_##member##_MASK) << \
					CEQ_CTRL_0_##member##_SHIFT)

#define CEQ_CTRL_1_LEN_SHIFT			0
#define CEQ_CTRL_1_PAGE_SIZE_SHIFT		28

#define CEQ_CTRL_1_LEN_MASK			0x1FFFFFU
#define CEQ_CTRL_1_PAGE_SIZE_MASK		0xFU

#define CEQ_CTRL_1_SET(val, member)		\
				(((val) & CEQ_CTRL_1_##member##_MASK) << \
					CEQ_CTRL_1_##member##_SHIFT)

#define EQ_ELEM_DESC_TYPE_SHIFT			0
#define EQ_ELEM_DESC_SRC_SHIFT			7
#define EQ_ELEM_DESC_SIZE_SHIFT			8
#define EQ_ELEM_DESC_WRAPPED_SHIFT		31

#define EQ_ELEM_DESC_TYPE_MASK			0x7FU
#define EQ_ELEM_DESC_SRC_MASK			0x1U
#define EQ_ELEM_DESC_SIZE_MASK			0xFFU
#define EQ_ELEM_DESC_WRAPPED_MASK		0x1U

#define EQ_ELEM_DESC_GET(val, member)		\
				(((val) >> EQ_ELEM_DESC_##member##_SHIFT) & \
				EQ_ELEM_DESC_##member##_MASK)

#define EQ_CONS_IDX_CONS_IDX_SHIFT		0
#define EQ_CONS_IDX_XOR_CHKSUM_SHIFT		24
#define EQ_CONS_IDX_INT_ARMED_SHIFT		31

#define EQ_CONS_IDX_CONS_IDX_MASK		0x1FFFFFU
#define EQ_CONS_IDX_XOR_CHKSUM_MASK		0xFU
#define EQ_CONS_IDX_INT_ARMED_MASK		0x1U

#define EQ_CONS_IDX_SET(val, member)		\
				(((val) & EQ_CONS_IDX_##member##_MASK) << \
				EQ_CONS_IDX_##member##_SHIFT)

#define EQ_CONS_IDX_CLEAR(val, member)		\
				((val) & (~(EQ_CONS_IDX_##member##_MASK \
					<< EQ_CONS_IDX_##member##_SHIFT)))

#define EQ_WRAPPED(eq)			((u32)(eq)->wrapped << EQ_VALID_SHIFT)

#define EQ_CONS_IDX(eq)		((eq)->cons_idx | \
				((u32)(eq)->wrapped << EQ_WRAPPED_SHIFT))

#define EQ_CONS_IDX_REG_ADDR(eq)	(((eq)->type == HINIC_AEQ) ? \
				HINIC_CSR_AEQ_CONS_IDX_ADDR((eq)->q_id) :\
				HINIC_CSR_CEQ_CONS_IDX_ADDR((eq)->q_id))

#define EQ_PROD_IDX_REG_ADDR(eq)	(((eq)->type == HINIC_AEQ) ? \
				HINIC_CSR_AEQ_PROD_IDX_ADDR((eq)->q_id) :\
				HINIC_CSR_CEQ_PROD_IDX_ADDR((eq)->q_id))

#define GET_EQ_NUM_PAGES(eq, size)		\
		((u16)(ALIGN((eq)->eq_len * (u32)(eq)->elem_size, (size)) \
		/ (size)))

#define GET_EQ_NUM_ELEMS(eq, pg_size)	((pg_size) / (u32)(eq)->elem_size)

#define GET_EQ_ELEMENT(eq, idx)		\
		(((u8 *)(eq)->virt_addr[(idx) / (eq)->num_elem_in_pg]) + \
		(((u32)(idx) & ((eq)->num_elem_in_pg - 1)) * (eq)->elem_size))

#define GET_AEQ_ELEM(eq, idx)		((struct hinic_aeq_elem *) \
					GET_EQ_ELEMENT((eq), (idx)))

#define GET_CEQ_ELEM(eq, idx)		((u32 *)GET_EQ_ELEMENT((eq), (idx)))

#define GET_CURR_AEQ_ELEM(eq)		GET_AEQ_ELEM((eq), (eq)->cons_idx)

#define GET_CURR_CEQ_ELEM(eq)		GET_CEQ_ELEM((eq), (eq)->cons_idx)

#define PAGE_IN_4K(page_size)		((page_size) >> 12)
#define EQ_SET_HW_PAGE_SIZE_VAL(eq) ((u32)ilog2(PAGE_IN_4K((eq)->page_size)))

#define ELEMENT_SIZE_IN_32B(eq)		(((eq)->elem_size) >> 5)
#define EQ_SET_HW_ELEM_SIZE_VAL(eq)	((u32)ilog2(ELEMENT_SIZE_IN_32B(eq)))

#define AEQ_DMA_ATTR_DEFAULT			0
#define CEQ_DMA_ATTR_DEFAULT			0

#define CEQ_LMT_KICK_DEFAULT			0

#define EQ_WRAPPED_SHIFT			20

#define	EQ_VALID_SHIFT				31

#define CEQE_TYPE_SHIFT				23
#define CEQE_TYPE_MASK				0x7

#define CEQE_TYPE(type)			(((type) >> CEQE_TYPE_SHIFT)	\
					& CEQE_TYPE_MASK)

#define CEQE_DATA_MASK				0x3FFFFFF
#define CEQE_DATA(data)				((data) & CEQE_DATA_MASK)

#define aeq_to_aeqs(eq) \
		container_of((eq) - (eq)->q_id, struct hinic_aeqs, aeq[0])

static u8 eq_cons_idx_checksum_set(u32 val)
{
	u8 checksum = 0;
	u8 idx;

	for (idx = 0; idx < 32; idx += 4)
		checksum ^= ((val >> idx) & 0xF);

	return (checksum & 0xF);
}

/**
 * set_eq_cons_idx - write the cons idx to the hw
 * @eq: The event queue to update the cons idx for
 * @arm_state: indicate whether report interrupts when generate eq element
 **/
static void set_eq_cons_idx(struct hinic_eq *eq, u32 arm_state)
{
	u32 eq_cons_idx, eq_wrap_ci, val;
	u32 addr = EQ_CONS_IDX_REG_ADDR(eq);

	eq_wrap_ci = EQ_CONS_IDX(eq);

	/* Read Modify Write */
	val = hinic_hwif_read_reg(eq->hwdev->hwif, addr);

	val = EQ_CONS_IDX_CLEAR(val, CONS_IDX) &
		EQ_CONS_IDX_CLEAR(val, INT_ARMED) &
		EQ_CONS_IDX_CLEAR(val, XOR_CHKSUM);

	/* Just aeq0 use int_arm mode for pmd drv to recv asyn event&mbox recv data */
	if (eq->q_id == 0)
		eq_cons_idx = EQ_CONS_IDX_SET(eq_wrap_ci, CONS_IDX) |
			EQ_CONS_IDX_SET(arm_state, INT_ARMED);
	else
		eq_cons_idx = EQ_CONS_IDX_SET(eq_wrap_ci, CONS_IDX) |
			EQ_CONS_IDX_SET(HINIC_EQ_NOT_ARMED, INT_ARMED);

	val |= eq_cons_idx;

	val |= EQ_CONS_IDX_SET(eq_cons_idx_checksum_set(val), XOR_CHKSUM);

	hinic_hwif_write_reg(eq->hwdev->hwif, addr, val);
}

/**
 * eq_update_ci - update the cons idx of event queue
 * @eq: the event queue to update the cons idx for
 **/
static void eq_update_ci(struct hinic_eq *eq)
{
	set_eq_cons_idx(eq, HINIC_EQ_ARMED);
}

struct hinic_ceq_ctrl_reg {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 q_id;
	u32 ctrl0;
	u32 ctrl1;
};

static int set_ceq_ctrl_reg(struct hinic_hwdev *hwdev, u16 q_id,
			    u32 ctrl0, u32 ctrl1)
{
	struct hinic_ceq_ctrl_reg ceq_ctrl;
	u16 in_size = sizeof(ceq_ctrl);

	memset(&ceq_ctrl, 0, in_size);
	ceq_ctrl.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	ceq_ctrl.func_id = hinic_global_func_id(hwdev);
	ceq_ctrl.q_id = q_id;
	ceq_ctrl.ctrl0 = ctrl0;
	ceq_ctrl.ctrl1 = ctrl1;

	return hinic_msg_to_mgmt_sync(hwdev, HINIC_MOD_COMM,
				     HINIC_MGMT_CMD_CEQ_CTRL_REG_WR_BY_UP,
				     &ceq_ctrl, in_size, NULL, NULL, 0);
}

/**
 * set_eq_ctrls - setting eq's ctrls registers
 * @eq: the event queue for setting
 **/
static int set_eq_ctrls(struct hinic_eq *eq)
{
	enum hinic_eq_type type = eq->type;
	struct hinic_hwif *hwif = eq->hwdev->hwif;
	struct irq_info *eq_irq = &eq->eq_irq;
	u32 addr, val, ctrl0, ctrl1, page_size_val, elem_size;
	u32 pci_intf_idx = HINIC_PCI_INTF_IDX(hwif);

	if (type == HINIC_AEQ) {
		/* set ctrl0 */
		addr = HINIC_CSR_AEQ_CTRL_0_ADDR(eq->q_id);

		val = hinic_hwif_read_reg(hwif, addr);

		val = AEQ_CTRL_0_CLEAR(val, INTR_IDX) &
			AEQ_CTRL_0_CLEAR(val, DMA_ATTR) &
			AEQ_CTRL_0_CLEAR(val, PCI_INTF_IDX) &
			AEQ_CTRL_0_CLEAR(val, INTR_MODE);

		ctrl0 = AEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX)|
			AEQ_CTRL_0_SET(AEQ_DMA_ATTR_DEFAULT, DMA_ATTR)	|
			AEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX)	|
			AEQ_CTRL_0_SET(HINIC_INTR_MODE_ARMED, INTR_MODE);

		val |= ctrl0;

		hinic_hwif_write_reg(hwif, addr, val);

		/* set ctrl1 */
		addr = HINIC_CSR_AEQ_CTRL_1_ADDR(eq->q_id);

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);
		elem_size = EQ_SET_HW_ELEM_SIZE_VAL(eq);

		ctrl1 = AEQ_CTRL_1_SET(eq->eq_len, LEN)		|
			AEQ_CTRL_1_SET(elem_size, ELEM_SIZE)	|
			AEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		hinic_hwif_write_reg(hwif, addr, ctrl1);

		return 0;
	} else {
		ctrl0 = CEQ_CTRL_0_SET(eq_irq->msix_entry_idx, INTR_IDX)|
			CEQ_CTRL_0_SET(CEQ_DMA_ATTR_DEFAULT, DMA_ATTR)	|
			CEQ_CTRL_0_SET(CEQ_LMT_KICK_DEFAULT, LIMIT_KICK) |
			CEQ_CTRL_0_SET(pci_intf_idx, PCI_INTF_IDX)	|
			CEQ_CTRL_0_SET(HINIC_INTR_MODE_ARMED, INTR_MODE);

		page_size_val = EQ_SET_HW_PAGE_SIZE_VAL(eq);

		ctrl1 = CEQ_CTRL_1_SET(eq->eq_len, LEN) |
			CEQ_CTRL_1_SET(page_size_val, PAGE_SIZE);

		/* set ceq ctrl reg through mgmt cpu */
		return set_ceq_ctrl_reg(eq->hwdev, eq->q_id, ctrl0, ctrl1);
	}
}

/**
 * ceq_elements_init - Initialize all the elements in the ceq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void ceq_elements_init(struct hinic_eq *eq, u32 init_val)
{
	u16 i;
	u32 *ceqe;

	for (i = 0; i < eq->eq_len; i++) {
		ceqe = GET_CEQ_ELEM(eq, i);
		*(ceqe) = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

/**
 * aeq_elements_init - initialize all the elements in the aeq
 * @eq: the event queue
 * @init_val: value to init with it the elements
 **/
static void aeq_elements_init(struct hinic_eq *eq, u32 init_val)
{
	struct hinic_aeq_elem *aeqe;
	u16 i;

	for (i = 0; i < eq->eq_len; i++) {
		aeqe = GET_AEQ_ELEM(eq, i);
		aeqe->desc = cpu_to_be32(init_val);
	}

	wmb();	/* Write the init values */
}

/**
 * alloc_eq_pages - allocate the pages for the queue
 * @eq: the event queue
 **/
static int alloc_eq_pages(struct hinic_eq *eq)
{
	struct hinic_hwif *hwif = eq->hwdev->hwif;
	u32 init_val;
	u64 dma_addr_size, virt_addr_size;
	u16 pg_num, i;
	int err;

	dma_addr_size = eq->num_pages * sizeof(*eq->dma_addr);
	virt_addr_size = eq->num_pages * sizeof(*eq->virt_addr);

	eq->dma_addr = (dma_addr_t *)kzalloc(dma_addr_size, GFP_KERNEL);
	if (!eq->dma_addr) {
		pr_err("Allocate dma addr array failed\n");
		return -ENOMEM;
	}

	eq->virt_addr = (u8 **)kzalloc(virt_addr_size, GFP_KERNEL);
	if (!eq->virt_addr) {
		pr_err("Allocate virt addr array failed\n");
		err = -ENOMEM;
		goto virt_addr_alloc_err;
	}

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++) {
		eq->virt_addr[pg_num] = (u8 *)dma_zalloc_coherent_aligned(
					eq->hwdev->dev_hdl,
					eq->page_size, &eq->dma_addr[pg_num],
					GFP_KERNEL);
		if (!eq->virt_addr[pg_num]) {
			err = -ENOMEM;
			goto dma_alloc_err;
		}

		hinic_hwif_write_reg(hwif,
				     HINIC_EQ_HI_PHYS_ADDR_REG(eq->type,
				     eq->q_id, pg_num),
				     upper_32_bits(eq->dma_addr[pg_num]));

		hinic_hwif_write_reg(hwif,
				     HINIC_EQ_LO_PHYS_ADDR_REG(eq->type,
				     eq->q_id, pg_num),
				     lower_32_bits(eq->dma_addr[pg_num]));
	}

	init_val = EQ_WRAPPED(eq);

	if (eq->type == HINIC_AEQ)
		aeq_elements_init(eq, init_val);
	else
		ceq_elements_init(eq, init_val);

	return 0;

dma_alloc_err:
	for (i = 0; i < pg_num; i++)
		dma_free_coherent(eq->hwdev->dev_hdl, eq->page_size,
				  eq->virt_addr[i], eq->dma_addr[i]);

virt_addr_alloc_err:
	kfree(eq->dma_addr);
	return err;
}

/**
 * free_eq_pages - free the pages of the queue
 * @eq: the event queue
 **/
static void free_eq_pages(struct hinic_eq *eq)
{
	struct hinic_hwdev *hwdev = eq->hwdev;
	u16 pg_num;

	for (pg_num = 0; pg_num < eq->num_pages; pg_num++)
		dma_free_coherent(hwdev->dev_hdl, eq->page_size,
				  eq->virt_addr[pg_num],
				  eq->dma_addr[pg_num]);

	kfree(eq->virt_addr);
	kfree(eq->dma_addr);
}

#define MSIX_ENTRY_IDX_0 (0)

/**
 * init_eq - initialize eq
 * @eq:	the event queue
 * @hwdev: the pointer to the private hardware device object
 * @q_id: Queue id number
 * @q_len: the number of EQ elements
 * @type: the type of the event queue, ceq or aeq
 * @page_size: the page size of the event queue
 * @entry: msix entry associated with the event queue
 * Return: 0 - Success, Negative - failure
 **/
static int init_eq(struct hinic_eq *eq, struct hinic_hwdev *hwdev, u16 q_id,
		   u16 q_len, enum hinic_eq_type type, u32 page_size,
		   __rte_unused struct irq_info *entry)
{
	int err = 0;

	eq->hwdev = hwdev;
	eq->q_id = q_id;
	eq->type = type;
	eq->page_size = page_size;
	eq->eq_len = q_len;

	/* clear eq_len to force eqe drop in hardware */
	if (eq->type == HINIC_AEQ) {
		hinic_hwif_write_reg(eq->hwdev->hwif,
				     HINIC_CSR_AEQ_CTRL_1_ADDR(eq->q_id), 0);
	} else {
		err = set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);
		if (err) {
			dev_err(hwdev->dev_hdl, "Set ceq control registers ctrl0[0] ctrl1[0] failed\n");
			return err;
		}
	}

	eq->cons_idx = 0;
	eq->wrapped = 0;

	eq->elem_size = (type == HINIC_AEQ) ?
			HINIC_AEQE_SIZE : HINIC_CEQE_SIZE;
	eq->num_pages = GET_EQ_NUM_PAGES(eq, page_size);
	eq->num_elem_in_pg = GET_EQ_NUM_ELEMS(eq, page_size);

	if (eq->num_elem_in_pg & (eq->num_elem_in_pg - 1)) {
		dev_err(hwdev->dev_hdl, "Number element in eq page is not power of 2\n");
		return -EINVAL;
	}

	if (eq->num_pages > HINIC_EQ_MAX_PAGES) {
		dev_err(hwdev->dev_hdl, "Too many pages for eq, num_pages: %d\n",
			eq->num_pages);
		return -EINVAL;
	}

	err = alloc_eq_pages(eq);
	if (err) {
		dev_err(hwdev->dev_hdl, "Allocate pages for eq failed\n");
		return err;
	}

	/* pmd use MSIX_ENTRY_IDX_0*/
	eq->eq_irq.msix_entry_idx = MSIX_ENTRY_IDX_0;

	err = set_eq_ctrls(eq);
	if (err) {
		dev_err(hwdev->dev_hdl, "Init eq control registers failed\n");
		goto init_eq_ctrls_err;
	}

	hinic_hwif_write_reg(eq->hwdev->hwif, EQ_PROD_IDX_REG_ADDR(eq), 0);
	set_eq_cons_idx(eq, HINIC_EQ_ARMED);

	if (eq->q_id == 0)
		hinic_set_msix_state(hwdev, 0, HINIC_MSIX_ENABLE);

	eq->poll_retry_nr = HINIC_RETRY_NUM;

	return 0;

init_eq_ctrls_err:
	free_eq_pages(eq);

	return err;
}

/**
 * remove_eq - remove eq
 * @eq:	the event queue
 **/
static void remove_eq(struct hinic_eq *eq)
{
	struct irq_info *entry = &eq->eq_irq;

	if (eq->type == HINIC_AEQ) {
		if (0 == eq->q_id)
			hinic_set_msix_state(eq->hwdev, entry->msix_entry_idx,
					     HINIC_MSIX_DISABLE);

		/* clear eq_len to avoid hw access host memory */
		hinic_hwif_write_reg(eq->hwdev->hwif,
				     HINIC_CSR_AEQ_CTRL_1_ADDR(eq->q_id), 0);
	} else {
		(void)set_ceq_ctrl_reg(eq->hwdev, eq->q_id, 0, 0);
	}

	/* update cons_idx to avoid invalid interrupt */
	eq->cons_idx = (u16)hinic_hwif_read_reg(eq->hwdev->hwif,
						EQ_PROD_IDX_REG_ADDR(eq));
	set_eq_cons_idx(eq, HINIC_EQ_NOT_ARMED);

	free_eq_pages(eq);
}

/**
 * hinic_aeqs_init - init all the aeqs
 * @hwdev: the pointer to the private hardware device object
 * @num_aeqs: number of aeq
 * @msix_entries: msix entries associated with the event queues
 * Return: 0 - Success, Negative - failure
 **/
static int
hinic_aeqs_init(struct hinic_hwdev *hwdev, u16 num_aeqs,
		struct irq_info *msix_entries)
{
	struct hinic_aeqs *aeqs;
	int err;
	u16 i, q_id;

	aeqs = (struct hinic_aeqs *)kzalloc(sizeof(*aeqs), GFP_KERNEL);
	if (!aeqs)
		return -ENOMEM;

	hwdev->aeqs = aeqs;
	aeqs->hwdev = hwdev;
	aeqs->num_aeqs = num_aeqs;

	for (q_id = HINIC_AEQN_START; q_id < num_aeqs; q_id++) {
		err = init_eq(&aeqs->aeq[q_id], hwdev, q_id,
			      HINIC_DEFAULT_AEQ_LEN, HINIC_AEQ,
			      HINIC_EQ_PAGE_SIZE, &msix_entries[q_id]);
		if (err) {
			dev_err(hwdev->dev_hdl, "Init aeq %d failed\n", q_id);
			goto init_aeq_err;
		}
	}

	return 0;

init_aeq_err:
	for (i = 0; i < q_id; i++)
		remove_eq(&aeqs->aeq[i]);

	kfree(aeqs);

	return err;
}

/**
 * hinic_aeqs_free - free all the aeqs
 * @hwdev: the pointer to the private hardware device object
 **/
static void hinic_aeqs_free(struct hinic_hwdev *hwdev)
{
	struct hinic_aeqs *aeqs = hwdev->aeqs;
	u16 q_id;

	/* hinic pmd use aeq[1~3], aeq[0] used in kernel only */
	for (q_id = HINIC_AEQN_START; q_id < aeqs->num_aeqs ; q_id++)
		remove_eq(&aeqs->aeq[q_id]);

	kfree(aeqs);
}

void hinic_dump_aeq_info(struct hinic_hwdev *hwdev)
{
	struct hinic_eq *eq;
	u32 addr, ci, pi;
	int q_id;

	for (q_id = 0; q_id < hwdev->aeqs->num_aeqs; q_id++) {
		eq = &hwdev->aeqs->aeq[q_id];
		addr = EQ_CONS_IDX_REG_ADDR(eq);
		ci = hinic_hwif_read_reg(hwdev->hwif, addr);
		addr = EQ_PROD_IDX_REG_ADDR(eq);
		pi = hinic_hwif_read_reg(hwdev->hwif, addr);
		dev_err(hwdev->dev_hdl, "aeq id: %d, ci: 0x%x, pi: 0x%x\n",
			q_id, ci, pi);
	}
}

static int hinic_handle_aeqe(void *handle, enum hinic_aeq_type event,
		      u8 *data, u8 size, void *param)
{
	int rc = 0;

	switch (event) {
	case HINIC_MSG_FROM_MGMT_CPU:
		rc = hinic_mgmt_msg_aeqe_handler(handle, data, size, param);
		break;
	default:
		HINIC_PRINT_ERR("Unknown event type: 0x%x, aeqe data: 0x%lx size: %d\n",
				event, *(u64 *)data, size);
		rc = HINIC_RECV_NEXT_AEQE;
		break;
	}

	return rc;
}

/**
 * hinic_aeq_poll_msg - poll one or continue aeqe, and call dedicated process
 * @eq: aeq of the chip
 * @timeout: 0   - poll all aeqe in eq, used in interrupt mode,
 *           > 0 - poll aeq until get aeqe with 'last' field set to 1,
 *           used in polling mode.
 * @param: customized parameter
 * Return: 0 - Success, EIO - poll timeout, ENODEV - swe not support
 **/
int hinic_aeq_poll_msg(struct hinic_eq *eq, u32 timeout, void *param)
{
	struct hinic_aeq_elem *aeqe_pos;
	enum hinic_aeq_type event;
	u32 aeqe_desc = 0;
	u16 i;
	u8 size;
	int done = HINIC_ERROR;
	int err = -EFAULT;
	unsigned long end;

	for (i = 0; ((timeout == 0) && (i < eq->eq_len)) ||
	     ((timeout > 0) && (done != HINIC_OK) && (i < eq->eq_len)); i++) {
		err = -EIO;
		end = jiffies + msecs_to_jiffies(timeout);
		do {
			aeqe_pos = GET_CURR_AEQ_ELEM(eq);
			rmb();

			/* Data in HW is in Big endian Format */
			aeqe_desc = be32_to_cpu(aeqe_pos->desc);

			/* HW updates wrapped bit,
			 * when it adds eq element event
			 */
			if (EQ_ELEM_DESC_GET(aeqe_desc, WRAPPED)
			    != eq->wrapped) {
				err = 0;
				break;
			}

			if (timeout != 0)
				msleep(1);
		} while (time_before(jiffies, end));

		if (err != HINIC_OK) /*poll time out*/
			break;

		event = EQ_ELEM_DESC_GET(aeqe_desc, TYPE);
		if (EQ_ELEM_DESC_GET(aeqe_desc, SRC)) {
			dev_err(eq->hwdev, "AEQ sw event not support %d\n",
				event);
			return -ENODEV;

		} else {
			size = EQ_ELEM_DESC_GET(aeqe_desc, SIZE);
			done = hinic_handle_aeqe(eq->hwdev, event,
						 aeqe_pos->aeqe_data,
						 size, param);
		}

		eq->cons_idx++;
		if (eq->cons_idx == eq->eq_len) {
			eq->cons_idx = 0;
			eq->wrapped = !eq->wrapped;
		}
	}

	eq_update_ci(eq);

	return err;
}

/**
 * hinic_aeq_poll_msg - init aeqs
 * @nic_dev: pmd nic device
 * Return: 0 - Success, Negative - failure
 **/
int hinic_comm_aeqs_init(hinic_nic_dev *nic_dev)
{
	int rc;
	u16 num_aeqs;
	struct irq_info aeq_irqs[HINIC_MAX_AEQS];

	num_aeqs = HINIC_HWIF_NUM_AEQS(nic_dev->hwdev->hwif);
	if (num_aeqs < HINIC_MAX_AEQS) {
		dev_err(nic_dev->hwdev, "Warning: PMD need %d AEQs, Chip have %d\n",
			HINIC_MAX_AEQS, num_aeqs);
		return HINIC_ERROR;
	}

	memset(aeq_irqs, 0, sizeof(aeq_irqs));
	rc = hinic_aeqs_init(nic_dev->hwdev, num_aeqs, aeq_irqs);
	if (rc != HINIC_OK)
	    dev_err(nic_dev->hwdev, "Initialize aeqs failed, rc: %d\n", rc);

	return rc;
}

void hinic_comm_aeqs_free(hinic_nic_dev *nic_dev)
{
	hinic_aeqs_free(nic_dev->hwdev);
}