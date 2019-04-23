/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#include "hinic_pmd_dpdev.h"

static void parse_dev_cap(struct hinic_hwdev *dev,
			  struct hinic_dev_cap *dev_cap,
			  enum func_type type);

bool hinic_support_nic(struct hinic_hwdev *hwdev, struct nic_service_cap *cap)
{
	if (!hwdev)
		return false;

	if (!IS_NIC_TYPE(hwdev))
		return false;

	if (cap)
		memcpy(cap, &hwdev->cfg_mgmt->svc_cap.nic_cap, sizeof(*cap));

	return true;
}

static void hinic_parse_shared_res_cap(struct service_cap *cap,
					struct hinic_dev_cap *dev_cap,
					__rte_unused enum func_type type)
{
	struct host_shared_resource_cap *shared_cap = &cap->shared_res_cap;

	shared_cap->host_pctxs = dev_cap->host_pctx_num;

	if (dev_cap->host_sf_en)
		cap->sf_en = true;
	else
		cap->sf_en = false;

	shared_cap->host_cctxs = dev_cap->host_ccxt_num;
	shared_cap->host_scqs = dev_cap->host_scq_num;
	shared_cap->host_srqs = dev_cap->host_srq_num;
	shared_cap->host_mpts = dev_cap->host_mpt_num;

	printk("Get share resource capability: \n");
	printk("host_pctxs: 0x%x," "host_cctxs: 0x%x, "
			"host_scqs: 0x%x, host_srqs: 0x%x, host_mpts: 0x%x \n",
			shared_cap->host_pctxs, shared_cap->host_cctxs,
			shared_cap->host_scqs, shared_cap->host_srqs,
			shared_cap->host_mpts);
}

static void hinic_parse_l2nic_res_cap(struct service_cap *cap,
				struct hinic_dev_cap *dev_cap,
				enum func_type type)
{
	struct nic_service_cap *nic_cap = &cap->nic_cap;

	if (type == TYPE_PF || type == TYPE_PPF) {
		nic_cap->max_sqs = dev_cap->nic_max_sq + 1;
		nic_cap->max_rqs = dev_cap->nic_max_rq + 1;
		nic_cap->vf_max_sqs = dev_cap->nic_vf_max_sq + 1;
		nic_cap->vf_max_rqs = dev_cap->nic_vf_max_rq + 1;
	} else {
		nic_cap->max_sqs = dev_cap->nic_max_sq;
		nic_cap->max_rqs = dev_cap->nic_max_rq;
		nic_cap->vf_max_sqs = 0;
		nic_cap->vf_max_rqs = 0;
	}

	if (dev_cap->nic_lro_en)
		nic_cap->lro_en = true;
	else
		nic_cap->lro_en = false;

	nic_cap->lro_sz = dev_cap->nic_lro_sz;
	nic_cap->tso_sz = dev_cap->nic_tso_sz;

	printk("Get l2nic resource capability: \n");
	printk("max_sqs: 0x%x, max_rqs: 0x%x, vf_max_sqs: 0x%x, vf_max_rqs: 0x%x \n",
		nic_cap->max_sqs, nic_cap->max_rqs, nic_cap->vf_max_sqs, nic_cap->vf_max_rqs);
}

static int get_cap_from_fw(struct hinic_hwdev *dev, enum func_type type)
{
	int err;
	u16 in_len, out_len;
	struct hinic_dev_cap dev_cap;

	memset(&dev_cap, 0, sizeof(dev_cap));
	in_len = sizeof(dev_cap);
	out_len = in_len;
	dev_cap.mgmt_msg_head.resp_aeq_num = HINIC_AEQ1;
	err = hinic_msg_to_mgmt_sync(dev, HINIC_MOD_CFGM, HINIC_CFG_NIC_CAP,
				     &dev_cap, in_len, &dev_cap, &out_len, 0);
	if (err || dev_cap.mgmt_msg_head.status || !out_len) {
		dev_err(dev->dev_hdl, "Get capability from FW failed, err: %d, status: %d, out_len: %d\n",
			err, dev_cap.mgmt_msg_head.status, out_len);
		return -EFAULT;
	}

	parse_dev_cap(dev, &dev_cap, type);
	return 0;
}

static int get_dev_cap(struct hinic_hwdev *dev)
{
	int err;
	enum func_type type = HINIC_FUNC_TYPE(dev);

	switch (type) {
	case TYPE_PF:
	case TYPE_PPF:
		err = get_cap_from_fw(dev, type);
		if (err) {
			dev_err(dev->dev_hdl, "Get PF/PPF capability failed\n");
			return err;
		}
		break;
	default:
		dev_err(dev->dev_hdl, "Unsupported PCI function type\n");
		return -EINVAL;
	}

	return 0;
}

u16 hinic_func_max_qnum(void *hwdev)
{
	struct hinic_hwdev *dev = (struct hinic_hwdev *)hwdev;

	return dev->cfg_mgmt->svc_cap.max_sqs;
}

int init_cfg_mgmt(struct hinic_hwdev *dev)
{
	struct cfg_mgmt_info *cfg_mgmt;

	cfg_mgmt = (struct cfg_mgmt_info *)
		   kzalloc(sizeof(*cfg_mgmt), GFP_KERNEL);
	if (!cfg_mgmt) {
		dev_err(dev->dev_hdl, "Alloc cfg mgmt failed\n");
		return -ENOMEM;
	}

	dev->cfg_mgmt = cfg_mgmt;
	cfg_mgmt->hwdev = dev;

	return 0;
}

void free_cfg_mgmt(struct hinic_hwdev *dev)
{
	kfree(dev->cfg_mgmt);
	dev->cfg_mgmt = NULL;
}

static void hinic_parse_pub_res_cap(struct service_cap *cap,
			      struct hinic_dev_cap *dev_cap,
			      enum func_type type)
{
	struct dev_sf_svc_attr *attr = &cap->sf_svc_attr;

	if (dev_cap->sf_svc_attr & SF_SVC_FT_BIT)
		attr->ft_en = true;
	else
		attr->ft_en = false;

	if (dev_cap->sf_svc_attr & SF_SVC_RDMA_BIT)
		attr->rdma_en = true;
	else
		attr->rdma_en = false;

	if (type == TYPE_PPF) {
		/* For PPF's SF EN flag, we assign it in get_dynamic_res_cap().
		 * we only save its VF's flag.
		 */
		attr->sf_en_vf = dev_cap->sf_en_vf;
	} else if (type == TYPE_PF) {
		if (dev_cap->sf_en_pf)
			cap->sf_en = true;
		else
			cap->sf_en = false;

		attr->sf_en_vf = dev_cap->sf_en_vf;
	}

	cap->host_id = dev_cap->host_id;
	cap->ep_id = dev_cap->ep_id;
	cap->interrupt_type = dev_cap->intr_type;
	cap->max_cos_id = dev_cap->max_cos_id;
	cap->er_id = dev_cap->er_id;
	cap->port_id = dev_cap->port_id;

	if (type == TYPE_PF || type == TYPE_PPF) {
		cap->max_vf = dev_cap->max_vf;
		cap->pf_num = dev_cap->pf_num;
		cap->pf_id_start = dev_cap->pf_id_start;
		cap->vf_num = dev_cap->vf_num;
		cap->vf_id_start = dev_cap->vf_id_start;
		/* FC need max queue number, but max queue number info is in
		  * l2nic cap, we also put max queue num info in public cap, so
		  * FC can get correct max queue number info.
		  */
		cap->max_sqs = dev_cap->nic_max_sq + 1;
		cap->max_rqs = dev_cap->nic_max_rq + 1;
	}

	cap->chip_svc_type = CFG_SVC_NIC_BIT0;
	cap->host_total_function = dev_cap->host_total_func;
	cap->host_oq_id_mask_val = dev_cap->host_oq_id_mask_val;
	cap->max_connect_num = dev_cap->max_conn_num;
	cap->max_stick2cache_num = dev_cap->max_stick2cache_num;
	cap->bfilter_start_addr = dev_cap->max_bfilter_start_addr;
	cap->bfilter_len = dev_cap->bfilter_len;
	cap->hash_bucket_num = dev_cap->hash_bucket_num;
	cap->dev_ver_info.cfg_file_ver = dev_cap->cfg_file_ver;
	cap->net_port_mode = dev_cap->net_port_mode;

	printk("Get public resource capability: \n");
	printk("host_id: 0x%x, ep_id: 0x%x, intr_type: 0x%x, max_cos_id: 0x%x, er_id: 0x%x, port_id: 0x%x \n",
		cap->host_id, cap->ep_id, cap->intr_chip_en,
		cap->max_cos_id, cap->er_id, cap->port_id);
	printk("host_total_function: 0x%x, host_oq_id_mask_val: 0x%x, net_port_mode: 0x%x, max_vf: 0x%x \n",
		cap->host_total_function, cap->host_oq_id_mask_val,
		cap->net_port_mode, cap->max_vf);
	printk("pf_num: 0x%x, pf_id_start: 0x%x, vf_num: 0x%x, vf_id_start: 0x%x \n",
		cap->pf_num, cap->pf_id_start,
		cap->vf_num, cap->vf_id_start);
}

static void parse_dev_cap(struct hinic_hwdev *dev,
			  struct hinic_dev_cap *dev_cap,
			  enum func_type type)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;

	/* Public resource */
	hinic_parse_pub_res_cap(cap, dev_cap, type);

	/* PPF managed dynamic resource */
	if (type == TYPE_PPF)
		hinic_parse_shared_res_cap(cap, dev_cap, type);

	/* L2 NIC resource */
	if (IS_NIC_TYPE(dev))
		hinic_parse_l2nic_res_cap(cap, dev_cap, type);
}

int hinic_init_capability(hinic_nic_dev *nic_dev)
{
	int err;
	struct hinic_hwdev *dev = nic_dev->hwdev;
	struct cfg_mgmt_info *cfg_mgmt = dev->cfg_mgmt;

	cfg_mgmt->svc_cap.sf_svc_attr.ft_pf_en = false;
	cfg_mgmt->svc_cap.sf_svc_attr.rdma_pf_en = false;

	cfg_mgmt->svc_cap.max_connect_num = 1024 * 1024; /* 1M */
	cfg_mgmt->svc_cap.max_stick2cache_num = 12 * 1024;

	cfg_mgmt->svc_cap.timer_en = true;
	cfg_mgmt->svc_cap.bloomfilter_en = false;

	err = get_dev_cap(dev);
	if (err)
		return err;

	/* support nic */
	err = hinic_support_nic(dev, &nic_dev->nic_cap);
	HINIC_ERR_RET(nic_dev, true != err, -ENOTSUP,
		      "Device do not support nic feature");

	return 0;
}
