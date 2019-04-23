/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC_COMPAT_H_
#define _HINIC_COMPAT_H_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#include <stdint.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_config.h>

typedef uint8_t   u8;
typedef int8_t    s8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef int32_t   s32;
typedef uint64_t  u64;


#ifndef dma_addr_t
typedef uint64_t  dma_addr_t;
#endif

#ifndef gfp_t
#define gfp_t unsigned
#endif

#ifndef bool
#define bool int
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef false
#define false	(0)
#endif

#ifndef true
#define true	(1)
#endif

#ifndef NULL
#define NULL ((void *)0)
#endif

#define HINIC_EEMPTY	(-4)
#define HINIC_ERROR	(-1)
#define HINIC_OK	(0)

#ifndef BIT
#define BIT(n) (1 << (n))
#endif

#define TEST_BIT(val, bit_shift) ((val) & (1UL << (bit_shift)))
#define SET_BIT(val, bit_shift)				\
	do {						\
		val = ((val) | (1UL << (bit_shift)));	\
	} while (0)

#define CLEAR_BIT(val, bit_shift)			\
	do {						\
		val = ((val) & (~(1UL << (bit_shift))));\
	} while (0)

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))
#define low_16_bits(x)   ((x) & 0xFFFF)
#define high_16_bits(x)  (((x) & 0xFFFF0000) >> 16)
#define make_64_bits(hi, lo) ((((u64)(hi)) << 32) | ((u64)((u32)(lo))))

/* Returns X / Y, rounding up.  X must be nonnegative to round correctly. */
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

#undef  ALIGN
#define ALIGN(x, a)  RTE_ALIGN(x, a)

#undef container_of
#define container_of(ptr, type, member) ({ \
		typeof(((type *)0)->member)(*__mptr) = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); })

#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))

#define HINIC_ASSERT_EN
#define RTE_LOGTYPE_HINIC RTE_LOGTYPE_USER7

#ifndef HINIC_NO_LOG
#define HINIC_LOG(log_level, fmt, args...) do {	\
	RTE_LOG(log_level, HINIC, fmt "\n", ##args);		\
} while (0)

#define HINIC_PRINT_INFO(fmt, args...) do {	\
	RTE_LOG(INFO, HINIC, fmt "\n", ##args);		\
} while (0)

#define HINIC_PRINT	HINIC_PRINT_INFO

#define HINIC_PRINT_WARN(fmt, args...) do {	\
	RTE_LOG(WARNING, HINIC, fmt "\n", ##args);		\
} while (0)

#define HINIC_PRINT_ERR(fmt, args...) do {	\
	RTE_LOG(ERR, HINIC, fmt "\n", ##args);		\
} while (0)

#else
#define HINIC_LOG(log_level, args...) do {} while (0)
#define HINIC_PRINT(log_level, args...) do {} while (0)
#define HINIC_PRINT_INFO(log_level, args...) do {} while (0)
#define HINIC_PRINT_WARN(log_level, args...) do {} while (0)
#define HINIC_PRINT_ERR(log_level, args...) do {} while (0)
#endif

#ifndef HINIC_NO_DEBUG
#define HINIC_DEBUG(fmt, args...) do {	\
	RTE_LOG(INFO, HINIC, fmt "\n", ##args);		\
} while (0)

#define HINIC_FN_ENTER(str, ...)	\
	HINIC_DEBUG("thread(%lu) enter: " str, pthread_self(), ##__VA_ARGS__)

#define HINIC_FN_LEAVE(str, ...)		\
	HINIC_DEBUG("thread(%lu) leave: " str, pthread_self(), ##__VA_ARGS__)

#else
#define HINIC_DEBUG(log_level, args...) do {} while (0)
#define HINIC_FN_ENTER(str, ...) do {} while (0)
#define HINIC_FN_LEAVE(str, ...) do {} while (0)
#endif

#define HINIC_ERR_RET(dev, cond, errcode, str, ...) do {		\
	if (unlikely(cond)) {						\
		HINIC_PRINT_ERR("%s: " str " |error(%d)", (dev)->proc_dev_name, \
		##__VA_ARGS__, errcode); \
		return errcode;						\
	}								\
} while (0)

#define HINIC_WARN_RET(dev, cond, errcode, str, ...) do {		\
	if (unlikely(cond)) {						\
		HINIC_PRINT_WARN("%s: " str " |error(%d)", (dev)->proc_dev_name,\
		##__VA_ARGS__, errcode); \
		return errcode;						\
	}								\
} while (0)

#define HINIC_ERR_HANDLE_RET(cond, handle, str, ...) do {		\
	if (unlikely(cond)) {						\
		HINIC_PRINT_ERR(str, ##__VA_ARGS__); \
		handle;							\
		return HINIC_ERROR;					\
	}								\
} while (0)

#define HINIC_ERR_HANDLE(cond, handle, str, ...) do {			\
	if (unlikely(cond)) {						\
		HINIC_PRINT_ERR(str, ##__VA_ARGS__); \
		handle;							\
	}								\
} while (0)

#ifdef HINIC_ASSERT_EN
#define HINIC_ASSERT(exp)		\
	if (!(exp)) {                            \
		rte_panic("line%d\tassert \"" #exp "\" failed\n", __LINE__); \
	}
#else
#define HINIC_ASSERT(exp)	do {} while (0)
#endif

#define HINIC_BUG_ON(x) HINIC_ASSERT(!(x))

/* common definition */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#define ETH_HLEN			14
#define ETH_CRC_LEN			4
#define VLAN_PRIO_SHIFT			13
#define VLAN_N_VID			4096

/* bit order interface */
#define cpu_to_be16(o) rte_cpu_to_be_16(o)
#define cpu_to_be32(o) rte_cpu_to_be_32(o)
#define cpu_to_be64(o) rte_cpu_to_be_64(o)
#define cpu_to_le32(o) rte_cpu_to_le_32(o)
#define be16_to_cpu(o) rte_be_to_cpu_16(o)
#define be32_to_cpu(o) rte_be_to_cpu_32(o)
#define be64_to_cpu(o) rte_be_to_cpu_64(o)
#define le32_to_cpu(o) rte_le_to_cpu_32(o)

/* virt memory and dma phy memory */
#define wmb() rte_wmb()
#define rmb()  rte_rmb()
#define mb()   rte_mb()
#define smp_mb()	rte_smp_mb()
#define smp_rmb()	rte_smp_rmb()
#define smp_wmb()	rte_smp_wmb()
#define __iomem
#define __force
#define GFP_KERNEL	0
#define PAGE_SHIFT	12
#define PAGE_SIZE	RTE_PGSIZE_4K
#define HINIC_MEM_ALLOC_ALIGNE_MIN	8

static inline int hinic_test_bit(int nr, volatile unsigned long *addr)
{
	int res;

	mb();
	res = ((*addr) & (1UL << nr)) != 0;
	mb();
	return res;
}

static inline void hinic_set_bit(unsigned int nr, volatile unsigned long *addr)
{
	__sync_fetch_and_or(addr, (1UL << nr));
}

static inline void hinic_clear_bit(int nr, volatile unsigned long *addr)
{
	__sync_fetch_and_and(addr, ~(1UL << nr));
}

static inline int hinic_test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = (1UL << nr);

	return __sync_fetch_and_and(addr, ~mask) & mask;
}

static inline int hinic_test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = (1UL << nr);

	return __sync_fetch_and_or(addr, mask) & mask;
}

void *dma_zalloc_coherent(void *dev, size_t size, dma_addr_t *dma_handle,
			  gfp_t flag);
void *dma_zalloc_coherent_aligned(void *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t flag);
void *dma_zalloc_coherent_aligned256k(void *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t flag);
void dma_free_coherent(void *dev, size_t size, void *virt, dma_addr_t phys);

/* dma pool alloc and free */
#define	pci_pool dma_pool
#define	pci_pool_alloc(pool, flags, handle) dma_pool_alloc(pool, flags, handle)
#define	pci_pool_free(pool, vaddr, addr) dma_pool_free(pool, vaddr, addr)

struct dma_pool *dma_pool_create(const char *name, void *dev, size_t size,
				size_t align, size_t boundary);
void dma_pool_destroy(struct dma_pool *pool);
void* dma_pool_alloc(struct pci_pool *pool, int flags, dma_addr_t *dma_addr);
void dma_pool_free(struct pci_pool *pool, void *vaddr, dma_addr_t dma);

/* kmalloc and kfree */
#define HINIC_MEM_ALLOC(size, flag) rte_zmalloc(NULL, size, HINIC_MEM_ALLOC_ALIGNE_MIN)
#define HINIC_MEM_FREE(ptr) rte_free(ptr)

#define kzalloc(size, flag) rte_zmalloc(NULL, size, HINIC_MEM_ALLOC_ALIGNE_MIN)
#define kzalloc_aligned(size, flag) rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE)
#define kfree(ptr)            rte_free(ptr)

/* mmio interface */
static inline void writel(u32 value, volatile void  *addr)
{
	*(volatile u32 *)addr = value;
}

static inline u32 readl(const volatile void *addr)
{
	return *(const volatile u32 *)addr;
}

#define HINIC_REG_WRITE32(value, reg) writel((value), (reg))
#define HINIC_REG_READ32(reg) readl((reg))
#define __raw_writel(value, reg) writel((value), (reg))
#define __raw_readl(reg) readl((reg))

/* atomic interface */
#define hinic_atomic32_t rte_atomic32_t
#define hinic_atomic64_t rte_atomic64_t
#define HINIC_ATOMIC32_INC(i32_ptr) rte_atomic32_inc(i32_ptr)
#define HINIC_ATOMIC32_DEC(i32_ptr) rte_atomic32_dec(i32_ptr)
#define HINIC_ATOMIC32_SET(i32_ptr, val) rte_atomic32_set(i32_ptr, val)
#define HINIC_ATOMIC32_READ(i32_ptr) rte_atomic32_read(i32_ptr)
#define HINIC_ATOMIC32_ADD(val, i32_ptr) rte_atomic32_add(i32_ptr, val)
#define HINIC_ATOMIC32_SUB(val, i32_ptr) rte_atomic32_sub(i32_ptr, val)
#define HINIC_ATOMIC32_ADD_RETURN(val, i32_ptr)	\
	rte_atomic32_add_return(i32_ptr, val)
#define HINIC_ATOMIC32_SUB_RETURN(val, i32_ptr) \
	rte_atomic32_sub_return(i32_ptr, val)

#define atomic16_t rte_atomic16_t
#define atomic32_t rte_atomic32_t
#define atomic64_t rte_atomic64_t

#define atomic16_init(i16_ptr) rte_atomic16_init(i16_ptr)
#define atomic16_inc(i16_ptr) rte_atomic16_inc(i16_ptr)
#define atomic16_dec(i16_ptr) rte_atomic16_dec(i16_ptr)
#define atomic16_set(i16_ptr, val) rte_atomic16_set(i16_ptr, val)
#define atomic16_read(i16_ptr) rte_atomic16_read(i16_ptr)

#define atomic_inc(i32_ptr) rte_atomic32_inc(i32_ptr)
#define atomic_dec(i32_ptr) rte_atomic32_dec(i32_ptr)
#define atomic_set(i32_ptr, val) rte_atomic32_set(i32_ptr, val)
#define atomic_read(i32_ptr) rte_atomic32_read(i32_ptr)
#define atomic_add(val, i32_ptr) rte_atomic32_add(i32_ptr, val)
#define atomic_sub(val, i32_ptr) rte_atomic32_sub(i32_ptr, val)
#define atomic_add_return(val, i32_ptr) rte_atomic32_add_return(i32_ptr, val)
#define atomic_sub_return(val, i32_ptr) rte_atomic32_sub_return(i32_ptr, val)

/* Spinlock related interface */
#define hinic_spinlock_t rte_spinlock_t
#define HINIC_SPINLOCK_INIT(spinlock_prt) rte_spinlock_init(spinlock_prt)
#define HINIC_SPINLOCK_LOCK(spinlock_prt) rte_spinlock_lock(spinlock_prt)
#define HINIC_SPINLOCK_UNLOCK(spinlock_prt) rte_spinlock_unlock(spinlock_prt)

#define spinlock_t rte_spinlock_t
#define spin_lock_init(spinlock_prt) 	rte_spinlock_init(spinlock_prt)
#define spin_lock_deinit(lock)
#define spin_lock(spinlock_prt)		rte_spinlock_lock(spinlock_prt)
#define spin_unlock(spinlock_prt)	rte_spinlock_unlock(spinlock_prt)

/* printk interface */
#define pr_emerg(fmt, ...) \
	RTE_LOG(EMERG, HINIC, fmt, ##__VA_ARGS__)
#define pr_alert(fmt, ...) \
	RTE_LOG(ALERT, HINIC, fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	RTE_LOG(CRIT, HINIC, fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	RTE_LOG(ERR, HINIC, fmt, ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
	RTE_LOG(WARNING, HINIC, fmt, ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_notice(fmt, ...) \
	RTE_LOG(NOTICE, HINIC, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	RTE_LOG(INFO, HINIC, fmt, ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	RTE_LOG(INFO, HINIC, fmt, ##__VA_ARGS__)

#define dev_printk(level, fmt, args...)	\
	RTE_LOG(level, HINIC, fmt, ## args)

#define dev_err(x, args...) do {				\
		(void)x;	\
		dev_printk(ERR, args);	\
} while (0)

#define dev_info(x, args...) do {				\
		(void)x;	\
		dev_printk(INFO, ## args);	\
} while (0)

#define dev_warn(x, args...) do {				\
		(void)x;	\
		dev_printk(WARNING, ## args);	\
} while (0)

#define dev_warning(x, args...) do {				\
		(void)x;	\
		dev_printk(WARNING, ## args);	\
} while (0)

#define dev_debug(x, args...) do {				\
		(void)x;	\
		dev_printk(DEBUG, ## args);	\
} while (0)

#define printk	pr_info

/* hiovs time wait */
static inline unsigned long get_timeofday_ms(void)
{
	struct timeval tv;

	(void)gettimeofday(&tv, NULL);

	return (unsigned long)tv.tv_sec * 1000 + tv.tv_usec / 1000 ;
}

#define msleep(x) rte_delay_us((x) * 1000)
#define udelay(x) rte_delay_us(x)

#define jiffies	get_timeofday_ms()
#define msecs_to_jiffies(ms)	(ms)
#define time_before(now, end)	((now) < (end))

/* misc kernel utils */
static inline u16 ilog2(u32 n)
{
	u16 res = 0;

	while (n > 1) {
		n >>= 1;
		res++;
	}

	return res;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* _HINIC_COMPAT_H_ */
