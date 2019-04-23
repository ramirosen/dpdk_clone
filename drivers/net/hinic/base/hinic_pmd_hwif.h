/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_HWIF_H_
#define _HINIC_PMD_HWIF_H_

#define HINIC_WAIT_DOORBELL_AND_OUTBOUND_TIMEOUT	30000

struct io_mapping;
struct hinic_hwdev;

struct hinic_free_db_area {
	u32		db_idx[HINIC_DB_MAX_AREAS];

	u32		num_free;

	u32		alloc_pos;
	u32		return_pos;

	spinlock_t	idx_lock;
};

struct hinic_func_attr {
	u16			func_global_idx;
	u8			port_to_port_idx;
	u8			pci_intf_idx;
	u8			vf_in_pf;
	enum func_type		func_type;

	u8			mpf_idx;

	u8			ppf_idx;

	u16			num_irqs;		/* max: 2 ^ 15 */
	u8			num_aeqs;		/* max: 2 ^ 3 */
	u8			num_ceqs;		/* max: 2 ^ 7 */

	u8			num_dma_attr;		/* max: 2 ^ 6 */

	u16			global_vf_id_of_pf;
};

struct hinic_hwif {
	u8 __iomem			*cfg_regs_base;
	u8 __iomem			*intr_regs_base;
	u64				db_base_phy;
	u8 __iomem			*db_base;
	struct io_mapping		*dwqe_mapping;

	struct hinic_free_db_area	free_db_area;

	struct hinic_func_attr		attr;
};

static inline u32 hinic_hwif_read_reg(struct hinic_hwif *hwif, u32 reg)
{
	return be32_to_cpu(readl(hwif->cfg_regs_base + reg));
}

static inline void hinic_hwif_write_reg(struct hinic_hwif *hwif, u32 reg,
					u32 val)
{
	writel(cpu_to_be32(val), hwif->cfg_regs_base + reg);
}

void hinic_set_pf_status(struct hinic_hwif *hwif, enum hinic_pf_status status);

enum hinic_pf_status hinic_get_pf_status(struct hinic_hwif *hwif);

void hinic_enable_doorbell(struct hinic_hwif *hwif);

void hinic_disable_doorbell(struct hinic_hwif *hwif);

int hinic_alloc_db_addr(void *hwdev, void __iomem **db_base,
			void __iomem **dwqe_base);

void hinic_free_db_addr(void *hwdev, void __iomem *db_base,
			void __iomem *dwqe_base);

void hinic_set_msix_state(void *hwdev, u16 msix_idx,
			  enum hinic_msix_state flag);

u8 hinic_ppf_idx(void *hwdev);

int hinic_init_hwif(struct hinic_hwdev *hwdev, void *cfg_reg_base,
		    void *intr_reg_base, u64 db_base_phy,
		    void *db_base, void *dwqe_mapping);

#endif /* _HINIC_PMD_HWIF_H_ */
