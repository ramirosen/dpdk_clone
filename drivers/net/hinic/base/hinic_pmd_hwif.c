/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include "hinic_pmd_dpdev.h"

#define HINIC_CFG_REGS_BAR	0
#define HINIC_INTR_MSI_BAR	2
#define HINIC_DB_MEM_BAR	4
#define HINIC_ASSERT_ON		1

/* hinic internal functions */
static void hinic_parse_hwif_attr(hinic_nic_dev *nic_dev);
static void init_db_area_idx(struct hinic_free_db_area *free_db_area);
static int get_db_idx(struct hinic_hwif *hwif, u32 *idx);
static void free_db_idx(struct hinic_hwif *hwif, u32 idx);
static void set_hwif_attr(struct hinic_hwif *hwif, u32 attr0,
			  u32 attr1, u32 attr2);
static void get_hwif_attr(struct hinic_hwif *hwif);
static int hwif_ready(struct hinic_hwdev *hwdev);
static enum hinic_doorbell_ctrl hinic_get_doorbell_ctrl_status(struct hinic_hwif *hwif);
static enum hinic_outbound_ctrl hinic_get_outbound_ctrl_status(struct hinic_hwif *hwif);
static int wait_until_doorbell_and_outbound_enabled(struct hinic_hwif *hwif);

static inline void __iomem *
io_mapping_map_wc(struct io_mapping *mapping, unsigned long offset)
{
	/* io_mapping only for compile using hinic kernel, dwqe not support */
	u32 hinic_assert = HINIC_ASSERT_ON;

	HINIC_BUG_ON(hinic_assert);

	return ((char __force __iomem *) mapping) + offset;
}

static inline void
io_mapping_unmap(void __iomem *vaddr)
{
	/* io_mapping only for compile using hinic kernel, dwqe not support */
	u32 hinic_assert = HINIC_ASSERT_ON;
	HINIC_BUG_ON(hinic_assert);

	*((u32 *)vaddr) = 0;
}

/**
 * hwif_ready - test if the HW initialization passed
 * @hwdev: the pointer to the private hardware device object
 * Return: 0 - success, negative - failure
 **/
static int hwif_ready(struct hinic_hwdev *hwdev)
{
	u32 addr, attr1;

	addr   = HINIC_CSR_FUNC_ATTR1_ADDR;
	attr1  = hinic_hwif_read_reg(hwdev->hwif, addr);

	if (!HINIC_AF1_GET(attr1, MGMT_INIT_STATUS))
		return -EBUSY;

	return 0;
}

/**
 * set_hwif_attr - set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 * @attr0: the first attribute that was read from the hw
 * @attr1: the second attribute that was read from the hw
 * @attr2: the third attribute that was read from the hw
 **/
static void set_hwif_attr(struct hinic_hwif *hwif, u32 attr0, u32 attr1,
			  u32 attr2)
{
	hwif->attr.func_global_idx = HINIC_AF0_GET(attr0, FUNC_GLOBAL_IDX);
	hwif->attr.port_to_port_idx = HINIC_AF0_GET(attr0, P2P_IDX);
	hwif->attr.pci_intf_idx = HINIC_AF0_GET(attr0, PCI_INTF_IDX);
	hwif->attr.vf_in_pf = HINIC_AF0_GET(attr0, VF_IN_PF);
	hwif->attr.func_type = HINIC_AF0_GET(attr0, FUNC_TYPE);

	hwif->attr.ppf_idx = HINIC_AF1_GET(attr1, PPF_IDX);

	hwif->attr.num_aeqs = BIT(HINIC_AF1_GET(attr1, AEQS_PER_FUNC));
	hwif->attr.num_ceqs = BIT(HINIC_AF1_GET(attr1, CEQS_PER_FUNC));
	hwif->attr.num_irqs = BIT(HINIC_AF1_GET(attr1, IRQS_PER_FUNC));
	hwif->attr.num_dma_attr = BIT(HINIC_AF1_GET(attr1, DMA_ATTR_PER_FUNC));

	hwif->attr.global_vf_id_of_pf = HINIC_AF2_GET(attr2,
						      GLOBAL_VF_ID_OF_PF);
}

/**
 * get_hwif_attr - read and set the attributes as members in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_hwif_attr(struct hinic_hwif *hwif)
{
	u32 addr, attr0, attr1, attr2;

	addr   = HINIC_CSR_FUNC_ATTR0_ADDR;
	attr0  = hinic_hwif_read_reg(hwif, addr);

	addr   = HINIC_CSR_FUNC_ATTR1_ADDR;
	attr1  = hinic_hwif_read_reg(hwif, addr);

	addr   = HINIC_CSR_FUNC_ATTR2_ADDR;
	attr2  = hinic_hwif_read_reg(hwif, addr);

	set_hwif_attr(hwif, attr0, attr1, attr2);
}

void hinic_set_pf_status(struct hinic_hwif *hwif, enum hinic_pf_status status)
{
	u32 attr5 = HINIC_AF5_SET(status, PF_STATUS);
	u32 addr  = HINIC_CSR_FUNC_ATTR5_ADDR;

	hinic_hwif_write_reg(hwif, addr, attr5);
}

enum hinic_pf_status hinic_get_pf_status(struct hinic_hwif *hwif)
{
	u32 attr5 = hinic_hwif_read_reg(hwif, HINIC_CSR_FUNC_ATTR5_ADDR);

	return HINIC_AF5_GET(attr5, PF_STATUS);
}

static enum hinic_doorbell_ctrl hinic_get_doorbell_ctrl_status(struct hinic_hwif *hwif)
{
	u32 attr4 = hinic_hwif_read_reg(hwif, HINIC_CSR_FUNC_ATTR4_ADDR);

	return HINIC_AF4_GET(attr4, DOORBELL_CTRL);
}

static enum hinic_outbound_ctrl hinic_get_outbound_ctrl_status(struct hinic_hwif *hwif)
{
	u32 attr4 = hinic_hwif_read_reg(hwif, HINIC_CSR_FUNC_ATTR4_ADDR);

	return HINIC_AF4_GET(attr4, OUTBOUND_CTRL);
}

void hinic_enable_doorbell(struct hinic_hwif *hwif)
{
	u32 addr, attr4;

	addr = HINIC_CSR_FUNC_ATTR4_ADDR;
	attr4 = hinic_hwif_read_reg(hwif, addr);

	attr4 = HINIC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HINIC_AF4_SET(ENABLE_DOORBELL, DOORBELL_CTRL);

	hinic_hwif_write_reg(hwif, addr, attr4);
}

void hinic_disable_doorbell(struct hinic_hwif *hwif)
{
	u32 addr, attr4;

	addr = HINIC_CSR_FUNC_ATTR4_ADDR;
	attr4 = hinic_hwif_read_reg(hwif, addr);

	attr4 = HINIC_AF4_CLEAR(attr4, DOORBELL_CTRL);
	attr4 |= HINIC_AF4_SET(DISABLE_DOORBELL, DOORBELL_CTRL);

	hinic_hwif_write_reg(hwif, addr, attr4);
}

/**
 * set_ppf - try to set hwif as ppf and set the type of hwif in this case
 * @hwif: the hardware interface of a pci function device
 **/
static void set_ppf(struct hinic_hwif *hwif)
{
	struct hinic_func_attr *attr = &hwif->attr;
	u32 addr, val, ppf_election;

	/* Read Modify Write */
	addr  = HINIC_CSR_PPF_ELECTION_ADDR;

	val = hinic_hwif_read_reg(hwif, addr);
	val = HINIC_PPF_ELECTION_CLEAR(val, IDX);

	ppf_election =  HINIC_PPF_ELECTION_SET(attr->func_global_idx, IDX);
	val |= ppf_election;

	hinic_hwif_write_reg(hwif, addr, val);

	/* Check PPF */
	val = hinic_hwif_read_reg(hwif, addr);

	attr->ppf_idx = HINIC_PPF_ELECTION_GET(val, IDX);
	if (attr->ppf_idx == attr->func_global_idx)
		attr->func_type = TYPE_PPF;
}

/**
 * get_mpf - get the mpf index into the hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void get_mpf(struct hinic_hwif *hwif)
{
	struct hinic_func_attr *attr = &hwif->attr;
	u32 mpf_election, addr;

	addr = HINIC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	mpf_election = hinic_hwif_read_reg(hwif, addr);
	attr->mpf_idx = HINIC_MPF_ELECTION_GET(mpf_election, IDX);
}

/**
 * set_mpf - try to set hwif as mpf and set the mpf idx in hwif
 * @hwif: the hardware interface of a pci function device
 **/
static void set_mpf(struct hinic_hwif *hwif)
{
	struct hinic_func_attr *attr = &hwif->attr;
	u32 addr, val, mpf_election;

	/* Read Modify Write */
	addr  = HINIC_CSR_GLOBAL_MPF_ELECTION_ADDR;

	val = hinic_hwif_read_reg(hwif, addr);

	val = HINIC_MPF_ELECTION_CLEAR(val, IDX);
	mpf_election = HINIC_MPF_ELECTION_SET(attr->func_global_idx, IDX);

	val |= mpf_election;
	hinic_hwif_write_reg(hwif, addr, val);

	get_mpf(hwif);
}

static void init_db_area_idx(struct hinic_free_db_area *free_db_area)
{
	u32 i;

	for (i = 0; i < HINIC_DB_MAX_AREAS; i++)
		free_db_area->db_idx[i] = i;

	free_db_area->alloc_pos = 0;
	free_db_area->return_pos = 0;

	free_db_area->num_free = HINIC_DB_MAX_AREAS;

	spin_lock_init(&free_db_area->idx_lock);
}

static int get_db_idx(struct hinic_hwif *hwif, u32 *idx)
{
	struct hinic_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;
	u32 pg_idx;

	spin_lock(&free_db_area->idx_lock);

	if (free_db_area->num_free == 0) {
		spin_unlock(&free_db_area->idx_lock);
		return -ENOMEM;
	}

	free_db_area->num_free--;

	pos = free_db_area->alloc_pos++;
	pos &= HINIC_DB_MAX_AREAS - 1;

	pg_idx = free_db_area->db_idx[pos];

	free_db_area->db_idx[pos] = 0xFFFFFFFF;

	spin_unlock(&free_db_area->idx_lock);

	*idx = pg_idx;

	return 0;
}

static void free_db_idx(struct hinic_hwif *hwif, u32 idx)
{
	struct hinic_free_db_area *free_db_area = &hwif->free_db_area;
	u32 pos;

	spin_lock(&free_db_area->idx_lock);

	pos = free_db_area->return_pos++;
	pos &= HINIC_DB_MAX_AREAS - 1;

	free_db_area->db_idx[pos] = idx;

	free_db_area->num_free++;

	spin_unlock(&free_db_area->idx_lock);
}

void hinic_free_db_addr(void *hwdev, void __iomem *db_base,
			void __iomem *dwqe_base)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;
	u32 idx = DB_IDX(db_base, hwif->db_base);

	if (dwqe_base)
		io_mapping_unmap(dwqe_base);

	free_db_idx(hwif, idx);
}

int hinic_alloc_db_addr(void *hwdev, void __iomem **db_base,
			void __iomem **dwqe_base)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;
	u64 offset;
	u32 idx;
	int err;

	err = get_db_idx(hwif, &idx);
	if (err)
		return -EFAULT;

	*db_base = hwif->db_base + idx * HINIC_DB_PAGE_SIZE;

	if (!dwqe_base)
		return 0;

	offset = ((u64)idx) << PAGE_SHIFT;
	*dwqe_base = io_mapping_map_wc(hwif->dwqe_mapping, offset);
	if (!(*dwqe_base)) {
		hinic_free_db_addr(hwdev, *db_base, NULL);
		return -EFAULT;
	}

	return 0;
}

void hinic_set_msix_state(void *hwdev, u16 msix_idx, enum hinic_msix_state flag)
{
	struct hinic_hwdev *hw = (struct hinic_hwdev *)hwdev;
	struct hinic_hwif *hwif = hw->hwif;
	u32 offset = msix_idx * HINIC_PCI_MSIX_ENTRY_SIZE
		+ HINIC_PCI_MSIX_ENTRY_VECTOR_CTRL;
	u32 mask_bits;

	/* vfio-pci does not mmap msi-x vector table to user space,
	 * we can not access the space when kernel driver is vfio-pci
	 */
	if (hw->pcidev_hdl->kdrv == RTE_KDRV_VFIO)
		return;

	mask_bits = readl(hwif->intr_regs_base + offset);
	mask_bits &= ~HINIC_PCI_MSIX_ENTRY_CTRL_MASKBIT;
	if (flag)
		mask_bits |= HINIC_PCI_MSIX_ENTRY_CTRL_MASKBIT;

	writel(mask_bits, hwif->intr_regs_base + offset);
}

static void disable_all_msix(struct hinic_hwdev *hwdev)
{
	u16 num_irqs = hwdev->hwif->attr.num_irqs;
	u16 i;

	for (i = 0; i < num_irqs; i++)
		hinic_set_msix_state(hwdev, i, HINIC_MSIX_DISABLE);
}

static int wait_until_doorbell_and_outbound_enabled(struct hinic_hwif *hwif)
{
	unsigned long end;
	enum hinic_doorbell_ctrl db_ctrl;
	enum hinic_outbound_ctrl outbound_ctrl;

	end = jiffies + msecs_to_jiffies(HINIC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT);
	do {
		db_ctrl = hinic_get_doorbell_ctrl_status(hwif);
		outbound_ctrl = hinic_get_outbound_ctrl_status(hwif);

		if (outbound_ctrl == ENABLE_OUTBOUND &&
		    db_ctrl == ENABLE_DOORBELL)
			return 0;

		msleep(1);
	} while (time_before(jiffies, end));

	return -EFAULT;
}

u16 hinic_global_func_id(void *hwdev)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;

	return hwif->attr.func_global_idx;
}

enum func_type hinic_func_type(void *hwdev)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;

	return hwif->attr.func_type;
}

u8 hinic_ppf_idx(void *hwdev)
{
	struct hinic_hwif *hwif = ((struct hinic_hwdev *)hwdev)->hwif;

	return hwif->attr.ppf_idx;
}

/**
 * hinic_init_hwif - initialize the hw interface
 * @hwdev: the pointer to the private hardware device object
 * @cfg_reg_base: base physical address of configuration registers
 * @intr_reg_base: base physical address of msi-x vector table
 * @db_base_phy: base physical address of doorbell registers
 * @db_base: base virtual address of doorbell registers
 * @dwqe_mapping: direct wqe io mapping address
 * Return: 0 - success, negative - failure
 **/
int hinic_init_hwif(struct hinic_hwdev *hwdev, void *cfg_reg_base,
		    void *intr_reg_base, u64 db_base_phy,
		    void *db_base, void *dwqe_mapping)
{
	struct hinic_hwif *hwif;
	int err;

	hwif = hwdev->hwif;

	hwif->cfg_regs_base = (u8 __iomem *)cfg_reg_base;
	hwif->intr_regs_base = (u8 __iomem *)intr_reg_base;

	hwif->db_base_phy = db_base_phy;
	hwif->db_base = (u8 __iomem *)db_base;
	hwif->dwqe_mapping = (struct io_mapping *)dwqe_mapping;
	init_db_area_idx(&hwif->free_db_area);

	get_hwif_attr(hwif);

	err = hwif_ready(hwdev);
	if (err) {
		pr_err("Hwif is not ready\n");
		goto hwif_ready_err;
	}

	err = wait_until_doorbell_and_outbound_enabled(hwif);
	if (err) {
		dev_err(hwdev->dev_hdl, "Hw doorbell/outbound is disabled\n");
		goto hwif_ready_err;
	}

	if (!HINIC_IS_VF(hwdev)) {
		set_ppf(hwif);

		if (HINIC_IS_PPF(hwdev))
			set_mpf(hwif);

		get_mpf(hwif);
	}

	return 0;

hwif_ready_err:
	spin_lock_deinit(&hwif->free_db_area.idx_lock);

	return err;
}

#define HINIC_HWIF_ATTR_REG_PRINT_NUM        (6)
#define HINIC_HWIF_APICMD_REG_PRINT_NUM      (2)
#define HINIC_HWIF_EQ_REG_PRINT_NUM          (2)

static void hinic_parse_hwif_attr(hinic_nic_dev *nic_dev)
{
	struct hinic_hwif *hwif;

	if (!nic_dev->hwdev || !nic_dev->hwdev->hwif) {
		dev_err(nic_dev, "Hwif not initialized\n");
		return;
	}

	hwif = nic_dev->hwdev->hwif;
	HINIC_PRINT("Device %s hwif attribute:", nic_dev->proc_dev_name);
	HINIC_PRINT("func_idx:%u, p2p_idx:%u, pciintf_idx:%u, "
		    "vf_in_pf:%u, ppf_idx:%u, global_vf_id:%u, func_type:%u",
		    hwif->attr.func_global_idx,
		    hwif->attr.port_to_port_idx, hwif->attr.pci_intf_idx,
		    hwif->attr.vf_in_pf, hwif->attr.ppf_idx,
		    hwif->attr.global_vf_id_of_pf, hwif->attr.func_type);
	HINIC_PRINT("num_aeqs:%u, num_ceqs:%u, num_irqs:%u, dma_attr:%u",
		    hwif->attr.num_aeqs, hwif->attr.num_ceqs,
		    hwif->attr.num_irqs, hwif->attr.num_dma_attr);
}

static void hinic_get_mmio(hinic_nic_dev *nic_dev, void **cfg_regs_base,
			  void **intr_base, void **db_base)
{
	struct rte_pci_device *pci_dev = nic_dev->hwdev->pcidev_hdl;

	*cfg_regs_base = pci_dev->mem_resource[HINIC_CFG_REGS_BAR].addr;
	*intr_base = pci_dev->mem_resource[HINIC_INTR_MSI_BAR].addr;
	*db_base = pci_dev->mem_resource[HINIC_DB_MEM_BAR].addr;
}

void hinic_hwif_res_free(hinic_nic_dev *nic_dev)
{
	rte_free(nic_dev->hwdev->hwif);
	nic_dev->hwdev->hwif = NULL;
}

int hinic_hwif_res_init(hinic_nic_dev *nic_dev)
{
	int err = HINIC_ERROR;
	void *cfg_regs_base, *db_base, *intr_base = NULL;
	struct hinic_hwdev	*hwdev = NULL;

	/* hinic related init */
	nic_dev->hwdev->hwif = (struct hinic_hwif *)rte_zmalloc("hinic_hwif",
			sizeof(*nic_dev->hwdev->hwif), RTE_CACHE_LINE_SIZE);
	HINIC_ERR_RET(nic_dev, NULL == nic_dev->hwdev->hwif, -ENOMEM,
		      "Alloc hwif mem failed");

	hwdev = nic_dev->hwdev;

	hinic_get_mmio(nic_dev, &cfg_regs_base, &intr_base, &db_base);

	err = hinic_init_hwif(hwdev, cfg_regs_base,
			      intr_base, 0, db_base, NULL);
	HINIC_ERR_HANDLE(err != HINIC_OK, goto init_hwif_err,
			 "Init hwif failed, nic_dev: %s, err: %d",
			 nic_dev->proc_dev_name, err);

	/* disable msix interrupt in hw device */
	disable_all_msix(hwdev);

	/* print hwif attributes */
	hinic_parse_hwif_attr(nic_dev);

	return HINIC_OK;

init_hwif_err:
	rte_free(nic_dev->hwdev->hwif);
	nic_dev->hwdev->hwif = NULL;

	return err;
}