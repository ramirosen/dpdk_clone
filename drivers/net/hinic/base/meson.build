sources = [
	'hinic_pmd_api_cmd.c',
	'hinic_pmd_cfg.c',
	'hinic_pmd_cmdq.c',
	'hinic_pmd_eqs.c',
	'hinic_pmd_hwdev.c',
	'hinic_pmd_hwif.c',
	'hinic_pmd_mgmt.c',
	'hinic_pmd_niccfg.c',
	'hinic_pmd_nicio.c',
	'hinic_pmd_qp.c',
	'hinic_pmd_wq.c'
]

headers = [
	'hinic_compat.h',
	'hinic_csr.h',
	'hinic_ctx_def.h',
	'hinic_pmd_api_cmd.h',
	'hinic_pmd_cfg.h',
	'hinic_pmd_cmdq.h',
	'hinic_pmd_dpdev.h',
	'hinic_pmd_eqs.h',
	'hinic_pmd_hwdev.h',
	'hinic_pmd_hw.h',
	'hinic_pmd_hwif.h',
	'hinic_pmd_hw_mgmt.h',
	'hinic_pmd_mgmt.h',
	'hinic_pmd_mgmt_interface.h',
	'hinic_pmd_niccfg.h',
	'hinic_pmd_nic.h',
	'hinic_pmd_nicio.h',
	'hinic_pmd_qp.h',
	'hinic_pmd_wq.h',
	'hinic_port_cmd.h',
	'hinic_qe_def.h'
]


deps += 'ethdev'
deps += 'pci'

error_cflags = ['-Wno-unused-value',
		'-Wno-unused-but-set-variable',
		'-Wno-unused-variable',
]
c_args = cflags

foreach flag: error_cflags
	if cc.has_argument(flag)
		c_args += flag
	endif
endforeach

base_lib = static_library('hinic_base', sources,
	dependencies: static_rte_eal,
	c_args: c_args)
base_objs = base_lib.extract_all_objects()
