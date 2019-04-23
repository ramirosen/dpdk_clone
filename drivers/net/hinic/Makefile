# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Huawei Technologies Co., Ltd

include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_hinic.a

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_hinic_version.map

LIBABIVER := 1

#
# Add extra flags for base driver files (also known as shared code)
# to disable warnings
#
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS_BASE_DRIVER = -wd593 -wd188
else ifeq ($(CONFIG_RTE_TOOLCHAIN_CLANG),y)
CFLAGS_BASE_DRIVER += -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing
CFLAGS_BASE_DRIVER += -Wno-format
CFLAGS_BASE_DRIVER += -Wno-missing-field-initializers
CFLAGS_BASE_DRIVER += -Wno-pointer-to-int-cast
CFLAGS_BASE_DRIVER += -Wno-format-nonliteral
CFLAGS_BASE_DRIVER += -Wno-unused-variable
else
CFLAGS_BASE_DRIVER  = -Wno-sign-compare
CFLAGS_BASE_DRIVER += -Wno-unused-value
CFLAGS_BASE_DRIVER += -Wno-unused-parameter
CFLAGS_BASE_DRIVER += -Wno-strict-aliasing
CFLAGS_BASE_DRIVER += -Wno-format
CFLAGS_BASE_DRIVER += -Wno-missing-field-initializers
CFLAGS_BASE_DRIVER += -Wno-pointer-to-int-cast
CFLAGS_BASE_DRIVER += -Wno-format-nonliteral
CFLAGS_BASE_DRIVER += -Wno-format-security
CFLAGS_BASE_DRIVER += -Wno-unused-variable

ifeq ($(shell test $(GCC_VERSION) -ge 44 && echo 1), 1)
CFLAGS_BASE_DRIVER += -Wno-unused-but-set-variable
endif

endif

OBJS_BASE_DRIVER=$(patsubst %.c,%.o,$(notdir $(wildcard $(SRCDIR)/base/*.c)))
$(foreach obj, $(OBJS_BASE_DRIVER), $(eval CFLAGS_$(obj)+=$(CFLAGS_BASE_DRIVER)))

VPATH += $(SRCDIR)/base

#
# all source are stored in SRCS-y
# base driver is based on the package of dpdk-hinic.2016.04.18.12.tar.gz.
#
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_api_cmd.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_cfg.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_cmdq.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_eqs.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_hwdev.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_hwif.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_mgmt.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_niccfg.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_nicio.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_qp.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_wq.c

SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_dpdev.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_rx.c
SRCS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += hinic_pmd_tx.c
# this lib depends upon:
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_eal lib/librte_ether
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_mempool lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_net lib/librte_hash
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_kvargs
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_net
DEPDIRS-$(CONFIG_RTE_LIBRTE_HINIC_PMD) += lib/librte_ring

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lrte_bus_pci

include $(RTE_SDK)/mk/rte.lib.mk
