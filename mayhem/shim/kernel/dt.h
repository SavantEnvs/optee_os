/* Host-build stand-in for core/include/kernel/dt.h: the CFG_DT_CACHED_NODE_INFO=n stubs only. */
#ifndef MAYHEM_SHIM_KERNEL_DT_H
#define MAYHEM_SHIM_KERNEL_DT_H
#include <stdint.h>

static inline int fdt_find_cached_parent_node(const void *fdt, int node_offset, int *parent_offset)
{
	(void)fdt; (void)node_offset; (void)parent_offset;
	return -1;
}

static inline int fdt_find_cached_node_phandle(const void *fdt, uint32_t phandle, int *node_offset)
{
	(void)fdt; (void)phandle; (void)node_offset;
	return -1;
}
#endif
