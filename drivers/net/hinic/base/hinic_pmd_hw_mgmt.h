/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_HW_MGMT_H_
#define _HINIC_PMD_HW_MGMT_H_

/* show each drivers only such as nic_service_cap,
 * toe_service_cap structure, but not show service_cap
 */
enum hinic_service_type {
	SERVICE_T_NIC = 0,
	SERVICE_T_MAX = 7,

	/* Only used for interruption resource management,
	 * mark the request module
	 */
	SERVICE_T_INTF   = (1 << 15),
	SERVICE_T_CQM    = (1 << 16),
};

enum intr_type {
	INTR_TYPE_MSIX,
	INTR_TYPE_MSI,
	INTR_TYPE_INT,
	/* PXE,OVS need single thread processing, synchronization
	* messages must use poll wait mechanism interface
	*/
	INTR_TYPE_NONE,
};

struct nic_service_cap {
	/* PF resources */
	u16 max_sqs;
	u16 max_rqs;

	/* VF resources, VF obtain them through the MailBox mechanism from
	 * corresponding PF
	 */
	u16 vf_max_sqs;
	u16 vf_max_rqs;

	bool lro_en;    /* LRO feature enable bit */
	u8 lro_sz;      /* LRO context space: n*16B */
	u8 tso_sz;      /* TSO context space: n*16B */
};

/* Defines the IRQ information structure*/
struct irq_info {
	u16 msix_entry_idx; /* IRQ corresponding index number */
	u32 irq_id;         /* the IRQ number from OS */
};

/* Define the version information structure*/
struct dev_version_info {
	u8 up_ver;       /* uP version, directly read from uP
			  * is not configured to file
			  */
	u8 ucode_ver;    /* The microcode version,
			  * read through the CMDq from microcode
			  */
	u8 cfg_file_ver; /* uP configuration file version */
	u8 sdk_ver;      /* SDK driver version */
	u8 hw_ver;       /* Hardware version */
};

/* Obtain service_cap.nic_cap.dev_nic_cap.max_sqs */
u16 hinic_func_max_qnum(void *hwdev);

u16 hinic_global_func_id(void *hwdev);	/* func_attr.glb_func_idx */

enum func_type {
	TYPE_PF,
	TYPE_VF,
	TYPE_PPF,
};

enum hinic_msix_state {
	HINIC_MSIX_ENABLE,
	HINIC_MSIX_DISABLE,
};

enum func_type hinic_func_type(void *hwdev);

#endif /* _HINIC_PMD_HW_MGMT_H_ */