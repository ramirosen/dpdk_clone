/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_PMD_MGMT_INTERFACE_H_
#define _HINIC_PMD_MGMT_INTERFACE_H_

/* cmd of mgmt CPU message for HILINK module */
enum hinic_hilink_cmd {
	HINIC_HILINK_CMD_GET_LINK_INFO		= 0x3,
	HINIC_HILINK_CMD_SET_LINK_SETTINGS	= 0x8,
};

enum hilink_info_print_event {
	HILINK_EVENT_LINK_UP = 1,
	HILINK_EVENT_LINK_DOWN,
	HILINK_EVENT_CABLE_PLUGGED,
	HILINK_EVENT_MAX_TYPE,
};

#define NIC_LRO_MAX_WQE_NUM	32
#define NIC_RSS_INDIR_SIZE	256
#define NIC_DCB_UP_MAX		0x8
#define NIC_RSS_KEY_SIZE        40
#define NIC_RSS_CMD_TEMP_ALLOC  0x01
#define NIC_RSS_CMD_TEMP_FREE   0x02

enum hinic_resp_aeq_num {
	HINIC_AEQ0 = 0,
	HINIC_AEQ1 = 1,
	HINIC_AEQ2 = 2,
	HINIC_AEQ3 = 3,
};

struct hinic_mgmt_msg_head {
	u8	status;
	u8	version;
	u8	resp_aeq_num;
	u8	rsvd0[5];
};

enum {
	RECYCLE_MODE_NIC = 0x0,
	RECYCLE_MODE_DPDK = 0x1,
};

struct hinic_fast_recycled_mode {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u8 fast_recycled_mode;/* 1: enable fast recyle, available in dpdk mode,
			       * 0: normal mode, available in kernel nic mode
			       */
	u8 rsvd1;
};

struct hinic_function_table {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rx_wqe_buf_size;
	u32	mtu;
};

struct hinic_cmd_qpn {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	base_qpn;
};

struct hinic_port_mac_set {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	vlan_id;
	u16	rsvd1;
	u8	mac[ETH_ALEN];
};

struct hinic_port_mac_update {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	vlan_id;
	u16	rsvd1;
	u8	old_mac[ETH_ALEN];
	u16	rsvd2;
	u8	new_mac[ETH_ALEN];
};

struct hinic_vport_state {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u8	state;
	u8	rsvd2[3];
};

struct hinic_port_state {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u8	state;
	u8	rsvd1[3];
};

struct hinic_mtu {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u32	mtu;
};

struct hinic_vlan_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	vlan_id;
};

struct hinic_get_link {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	link_status;
	u8	rsvd1;
};

#define HINIC_DEFAUT_PAUSE_CONFIG 1
struct hinic_pause_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u32	auto_neg;
	u32	rx_pause;
	u32	tx_pause;
};

struct hinic_port_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u8	port_type;
	u8	autoneg_cap;
	u8	autoneg_state;
	u8	duplex;
	u8	speed;
	u8	resv2[3];
};

struct hinic_set_autoneg {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	enable;	/* 1: enable , 0: disable */
};

struct hinic_up_ets_cfg {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u8 port_id;
	u8 rsvd1[3];
	u8 up_tc[HINIC_DCB_UP_MAX];
	u8 pg_bw[HINIC_DCB_PG_MAX];
	u8 pgid[HINIC_DCB_UP_MAX];
	u8 up_bw[HINIC_DCB_UP_MAX];
	u8 prio[HINIC_DCB_PG_MAX];
};

struct hinic_tso_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u8	tso_en;
	u8	resv2[3];
};

struct hinic_lro_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u8	lro_ipv4_en;
	u8	lro_ipv6_en;
	u8	lro_max_wqe_num;
	u8	resv2[13];
};

struct hinic_checksum_offload {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u32	rx_csum_offload;
};

struct hinic_vlan_offload {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	vlan_rx_offload;
	u8	rsvd1[5];
};

struct hinic_rx_mode_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u32	rx_mode;
};

/* rss */
struct nic_rss_indirect_tbl {
	u32 group_index;
	u32 offset;
	u32 size;
	u32 rsvd;
	u8 entry[NIC_RSS_INDIR_SIZE];
};

struct nic_rss_context_tbl {
	u32 group_index;
	u32 offset;
	u32 size;
	u32 rsvd;
	u32 ctx;
};

struct hinic_rss_config {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	rss_en;
	u8	template_id;
	u8	rq_priority_number;
	u8	rsvd1[3];
	u8	prio_tc[NIC_DCB_UP_MAX];
};

struct hinic_rss_template_mgmt {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	cmd;
	u8	template_id;
	u8	rsvd1[4];
};

struct hinic_rss_indir_table {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	template_id;
	u8	rsvd1;
	u8	indir[NIC_RSS_INDIR_SIZE];
};

struct hinic_rss_template_key {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	template_id;
	u8	rsvd1;
	u8	key[NIC_RSS_KEY_SIZE];
};

struct hinic_rss_engine_type {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	template_id;
	u8	hash_engine;
	u8	rsvd1[4];
};

struct hinic_rss_context_table {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	template_id;
	u8	rsvd1;
	u32	context;
};

struct hinic_port_link_status {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	link;
	u8	port_id;
};

struct hinic_cable_plug_event {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	plugged;	/* 0: unplugged, 1: plugged */
	u8	port_id;
};

struct hinic_link_err_event {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	err_type;
	u8	port_id;
};

enum link_err_status {
	LINK_ERR_MODULE_UNRECOGENIZED,
	LINK_ERR_NUM,
};

#define HINIC_PORT_STATS_VERSION	0

struct hinic_port_stats_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 stats_version;
	u32 stats_size;
};

struct hinic_port_qfilter_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 filter_enable;
	u8 filter_type;
	u8 qid;
	u8 rsvd2;
};

struct hinic_port_stats {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	struct hinic_phy_port_stats stats;
};

struct hinic_cmd_vport_stats {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	struct hinic_vport_stats stats;
};

struct hinic_clear_port_stats {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 rsvd;
	u32  stats_version;
	u32  stats_size;
};

struct hinic_clear_vport_stats {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 rsvd;
	u32  stats_version;
	u32  stats_size;
};

#define HINIC_COMPILE_TIME_LEN	20
struct hinic_version_info {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u8 ver[HINIC_FW_VERSION_NAME];
	u8 time[HINIC_COMPILE_TIME_LEN];
};

/* get or set loopback mode, need to modify by base API */
#define HINIC_INTERNAL_LP_MODE 5

#define ANTI_ATTACK_DEFAULT_CIR 500000
#define ANTI_ATTACK_DEFAULT_XIR 600000
#define ANTI_ATTACK_DEFAULT_CBS 10000000
#define ANTI_ATTACK_DEFAULT_XBS 12000000

/* set physical port Anti-Attack rate */
struct hinic_port_anti_attack_rate {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	enable; /* 1: enable rate-limiting, 0: disable rate-limiting */
	u32	cir;	/* Committed Information Rate */
	u32	xir;	/* eXtended Information Rate */
	u32	cbs;	/* Committed Burst Size */
	u32	xbs;	/* eXtended Burst Size */
};

struct hinic_l2nic_reset {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 rsvd1;
};

struct hinic_root_ctxt {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u16	rsvd1;
	u8	set_cmdq_depth;
	u8	cmdq_depth;
	u8	lro_en;
	u8	rsvd2;
	u8	ppf_idx;
	u8	rsvd3;
	u16	rq_depth;
	u16	rx_buf_sz;
	u16	sq_depth;
};

struct hinic_page_size {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_idx;
	u8	ppf_idx;
	u8	page_size;
	u32	rsvd;
};

struct hinic_dcb_state {
	u8 dcb_on;
	u8 default_cos;
	u8 up_cos[8];
};

struct hinic_vf_default_cos {
	u8	status;
	u8	version;
	u8	rsvd0[6];

	struct hinic_dcb_state state;
};

struct hinic_reset_link_cfg {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
};

struct hinic_set_vhd_mode {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16 func_id;
	u16 vhd_type;
	u16 rx_wqe_buffer_size;
	u16 rsvd;
};

struct hinic_vlan_filter {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u8	rsvd1[2];
	u32	vlan_filter_ctrl;
};

struct hinic_set_link_follow {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd0;
	u8	follow_status;
	u8	rsvd1[3];
};

struct hinic_link_mode_cmd {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
	u16	supported;	/* 0xFFFF represent Invalid value */
	u16	advertised;
};

struct hinic_clear_qp_resource {
	struct hinic_mgmt_msg_head mgmt_msg_head;

	u16	func_id;
	u16	rsvd1;
};

int hinic_init_function_table(void *hwdev, u16 rx_buf_sz);

int hinic_set_fast_recycle_mode(void *hwdev, u8 mode);

int hinic_get_base_qpn(void *hwdev, u16 *global_qpn);

int hinic_set_pagesize(void *hwdev, u8 page_size);

#endif /* _HINIC_PMD_MGMT_INTERFACE_H_ */