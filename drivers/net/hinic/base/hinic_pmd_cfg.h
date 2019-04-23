/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_CFG_H_
#define _HINIC_PMD_CFG_H_

#define CFG_MAX_CMD_TIMEOUT     8000 /* ms */

enum {
	SF_SVC_FT_BIT = (1 << 0),
	SF_SVC_RDMA_BIT = (1 << 1),
};

struct host_shared_resource_cap {
	u32 host_pctxs; /* Parent Context max 1M, IOE and FCoE max 8K flows */
	u32 host_cctxs; /* Child Context: max 8K */
	u32 host_scqs;  /* shared CQ, chip interface module uses 1 SCQ
			 * TOE/IOE/FCoE each uses 1 SCQ
			 * RoCE/IWARP uses multiple SCQs
			 * So 6 SCQ least
			 */
	u32 host_srqs; /* SRQ number: 256K */
	u32 host_mpts; /* MR number:1M */
};

struct dev_sf_svc_attr {
	bool ft_en;     /* business enable flag (not include RDMA) */
	bool ft_pf_en;  /* In FPGA Test VF resource is in PF or not,
			 * 0 - VF, 1 - PF, VF doesn't need this bit.
			 */

	bool rdma_en;
	bool rdma_pf_en; /* In FPGA Test VF RDMA resource is in PF or not,
			    * 0 - VF, 1 - PF, VF doesn't need this bit.
			    */
	u8 sf_en_vf;    /* SF_EN for PPF/PF's VF */
};

/* device capability */
struct service_cap {
	struct dev_sf_svc_attr sf_svc_attr;
	enum cfg_svc_type_en svc_type;		/* user input service type */
	enum cfg_svc_type_en chip_svc_type;	/* HW supported service type */

	/* Host global resources */
	u16 host_total_function;
	u8 host_oq_id_mask_val;
	u8 host_id;
	u8 ep_id;
	/* Don't get interrupt_type from firmware */
	enum intr_type interrupt_type;
	u8 intr_chip_en;
	u8 max_cos_id;	/* PF/VF's max cos id */
	u8 er_id;	/* PF/VF's ER */
	u8 port_id;	/* PF/VF's physical port */
	u8 max_vf;	/* max VF number that PF supported */
	bool sf_en;	/* stateful business status */
	u8 timer_en;	/* 0:disable, 1:enable */
	u8 bloomfilter_en; /* 0:disable, 1:enable*/
	u16 max_sqs;
	u16 max_rqs;

	/* PF BAT Bfliter CFG(16) is set when FT_EN=1 */
	u32 max_connect_num;	/* PF/VF maximum connection number(1M) */
	/* The maximum connections which can be stick to cache memory, max 1K */
	u16 max_stick2cache_num;
	/* Starting address in cache memory for bloom filter, 64Bytes aligned */
	u16 bfilter_start_addr;
	/* Length for bloom filter, aligned on 64Bytes. The size is length*64B.
	  * Bloom filter memory size + 1 must be power of 2.
	  * The maximum memory size of bloom filter is 4M
	  */
	u16 bfilter_len;
	/* The size of hash bucket tables, align on 64 entries.
	  *  Be used to AND (&) the hash value. Bucket Size +1 must be
	  *  power of 2.
	  *  The maximum number
	  * of hash bucket is 4M
	  */
	u16 hash_bucket_num;
	u8 net_port_mode; /* 0:ETH,1:FIC,2:4FC */

	u32 pf_num;
	u32 pf_id_start;
	u32 vf_num;
	u32 vf_id_start;

	struct host_shared_resource_cap shared_res_cap; /* shared capability */
	struct dev_version_info     dev_ver_info;       /* version */
	struct nic_service_cap      nic_cap;            /* NIC capability */
};

struct cfg_eq {
	enum hinic_service_type type;
	int eqn;
	int free; /* 1 - allocated, 0- freed */
};

struct cfg_eq_info {
	struct cfg_eq *eq;

	u8 num_ceq;
	u8 num_aeq;
	u8 num_eq;	/* num_eq = num_ceq + num_aeq */

	u8 num_ceq_remain;
};

struct cfg_mgmt_info {
	struct hinic_hwdev *hwdev;
	struct service_cap  svc_cap;
	struct cfg_eq_info  eq_info;
	u32 func_seq_num;   /* temporary */
};

enum cfg_sub_cmd {
	/* PPF(PF) <-> FW */
	HINIC_CFG_NIC_CAP = 0,
	CFG_FW_VERSION,
	CFG_UCODE_VERSION,
	HINIC_CFG_MBOX_CAP = 6
};

struct hinic_dev_cap {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	/* Public resource */
	u8 sf_svc_attr;
	u8 host_id;
	u8 sf_en_pf;
	u8 sf_en_vf;

	u8 ep_id;
	u8 intr_type;
	u8 max_cos_id;
	u8 er_id;
	u8 port_id;
	u8 max_vf;
	u16 svc_cap_en;
	u16 host_total_func;
	u8 host_oq_id_mask_val;
	u8 max_vf_cos_id;

	u32 max_conn_num;
	u16 max_stick2cache_num;
	u16 max_bfilter_start_addr;
	u16 bfilter_len;
	u16 hash_bucket_num;
	u8 cfg_file_ver;
	u8 net_port_mode;
	u8 valid_cos_bitmap;	/* every bit indicate cos is valid */
	u8 rsvd1;
	u32 pf_num;
	u32 pf_id_start;
	u32 vf_num;
	u32 vf_id_start;

	/* shared resource */
	u32 host_pctx_num;
	u8 host_sf_en;
	u8 rsvd2[3];
	u32 host_ccxt_num;
	u32 host_scq_num;
	u32 host_srq_num;
	u32 host_mpt_num;

	/* l2nic */
	u16 nic_max_sq;
	u16 nic_max_rq;
	u16 nic_vf_max_sq;
	u16 nic_vf_max_rq;
	u8 nic_lro_en;
	u8 nic_lro_sz;
	u8 nic_tso_sz;
	u8 rsvd3;

	/* RoCE */
	u32 roce_max_qp;
	u32 roce_max_cq;
	u32 roce_max_srq;
	u32 roce_max_mpt;

	u32 roce_vf_max_qp;
	u32 roce_vf_max_cq;
	u32 roce_vf_max_srq;
	u32 roce_vf_max_mpt;

	u32 roce_cmtt_cl_start;
	u32 roce_cmtt_cl_end;
	u32 roce_cmtt_cl_size;

	u32 roce_dmtt_cl_start;
	u32 roce_dmtt_cl_end;
	u32 roce_dmtt_cl_size;

	u32 roce_wqe_cl_start;
	u32 roce_wqe_cl_end;
	u32 roce_wqe_cl_size;

	/* IWARP */
	u32 iwarp_max_qp;
	u32 iwarp_max_cq;
	u32 iwarp_max_mpt;

	u32 iwarp_vf_max_qp;
	u32 iwarp_vf_max_cq;
	u32 iwarp_vf_max_mpt;

	u32 iwarp_cmtt_cl_start;
	u32 iwarp_cmtt_cl_end;
	u32 iwarp_cmtt_cl_size;

	u32 iwarp_dmtt_cl_start;
	u32 iwarp_dmtt_cl_end;
	u32 iwarp_dmtt_cl_size;

	u32 iwarp_wqe_cl_start;
	u32 iwarp_wqe_cl_end;
	u32 iwarp_wqe_cl_size;

	/* FCoE */
	u32 fcoe_max_qp;
	u32 fcoe_max_cq;
	u32 fcoe_max_srq;

	u32 fcoe_max_cctx;
	u32 fcoe_cctx_id_start;

	u8 fcoe_vp_id_start;
	u8 fcoe_vp_id_end;
	u8 rsvd4[2];

	/* IoE */
	u32 ioe_max_pctx;
	u32 ioe_max_cctx;

	/* ToE */
	u32 toe_max_pctx;
	u32 toe_max_cq;
	u32 toe_max_srq;
	u32 toe_srq_id_start;

	/* FC */
	u32 fc_max_pctx;
	u32 fc_max_scq;
	u32 fc_max_srq;

	u32 fc_max_cctx;
	u32 fc_cctx_id_start;

	u8 fc_vp_id_start;
	u8 fc_vp_id_end;
	u8 rsvd5[2];
};

int init_cfg_mgmt(struct hinic_hwdev *hwdev);
void free_cfg_mgmt(struct hinic_hwdev *hwdev);

/*for clear ucode&MIB stats*/
void hinic_clear_vport_stats(struct hinic_hwdev *hwdev);
void hinic_clear_phy_port_stats(struct hinic_hwdev *hwdev);

bool hinic_support_nic(struct hinic_hwdev *hwdev, struct nic_service_cap *cap);

#endif /* _HINIC_PMD_CFG_H_ */
