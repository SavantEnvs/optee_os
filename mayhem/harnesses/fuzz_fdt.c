/*
 * libfdt (core/lib/libfdt): read-only traversal of an arbitrary blob, then the read-write
 * API and overlay application on blobs that pass fdt_check_full().
 *
 * Input: data[0] bit 0 selects overlay mode; the blob(s) follow. Overlay mode splits the
 * remainder in two at the offset given by data[1] * 16.
 */
#include <libfdt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void walk(const void *fdt)
{
	char path[128];
	int depth = 0;
	int off = 0;
	int n = 0;

	(void)fdt_num_mem_rsv(fdt);
	(void)fdt_path_offset(fdt, "/");
	(void)fdt_path_offset(fdt, "/aliases");
	(void)fdt_get_alias(fdt, "serial0");
	(void)fdt_path_offset(fdt, "/chosen/stdout-path");

	for (off = fdt_next_node(fdt, -1, &depth); off >= 0 && depth >= 0;
	     off = fdt_next_node(fdt, off, &depth)) {
		int len = 0;
		int p = 0;

		(void)fdt_get_name(fdt, off, &len);
		(void)fdt_get_phandle(fdt, off);
		(void)fdt_get_path(fdt, off, path, sizeof(path));
		(void)fdt_node_check_compatible(fdt, off, "arm,pl011");
		(void)fdt_stringlist_count(fdt, off, "compatible");
		(void)fdt_stringlist_get(fdt, off, "compatible", 0, &len);
		(void)fdt_getprop(fdt, off, "reg", &len);
		(void)fdt_getprop(fdt, off, "status", &len);
		(void)fdt_address_cells(fdt, off);
		(void)fdt_size_cells(fdt, off);
		(void)fdt_subnode_offset(fdt, off, "child");
		(void)fdt_parent_offset(fdt, off);
		(void)fdt_supernode_atdepth_offset(fdt, off, 0, NULL);

		for (p = fdt_first_property_offset(fdt, off); p >= 0;
		     p = fdt_next_property_offset(fdt, p)) {
			const char *name = NULL;
			const void *val = fdt_getprop_by_offset(fdt, p, &name, &len);

			if (val && len > 0)
				(void)((const volatile uint8_t *)val)[len - 1];
			if (name)
				(void)strlen(name);
		}
		if (++n > 100000)
			break;
	}
}

static void rw_ops(const uint8_t *blob, size_t size)
{
	size_t room = size + 512;
	void *buf = malloc(room);
	int node = 0;

	if (!buf)
		return;
	if (fdt_open_into(blob, buf, room) == 0) {
		node = fdt_add_subnode(buf, 0, "mayhem");
		if (node >= 0) {
			(void)fdt_setprop_u32(buf, node, "reg", 0x1234);
			(void)fdt_setprop_string(buf, node, "compatible", "mayhem,test");
			(void)fdt_appendprop_string(buf, node, "compatible", "second");
			(void)fdt_delprop(buf, node, "reg");
			(void)fdt_del_node(buf, node);
		}
		node = fdt_path_offset(buf, "/");
		if (node >= 0)
			(void)fdt_setprop_string(buf, node, "model", "mayhem");
		(void)fdt_add_mem_rsv(buf, 0x1000, 0x1000);
		if (fdt_pack(buf) == 0)
			(void)fdt_check_full(buf, room);
		walk(buf);
	}
	free(buf);
}

static void overlay(const uint8_t *data, size_t size, size_t split)
{
	size_t blen = split;
	size_t olen = size - split;
	size_t room = blen + olen + 1024;
	void *base = NULL;
	void *ovl = NULL;

	if (blen < FDT_V17_SIZE || olen < FDT_V17_SIZE)
		return;
	base = malloc(room);
	ovl = malloc(olen);
	if (!base || !ovl)
		goto out;
	memcpy(ovl, data + split, olen);
	if (fdt_open_into(data, base, room) != 0)
		goto out;
	if (fdt_check_full(ovl, olen) != 0)
		goto out;
	if (fdt_overlay_apply(base, ovl) == 0)
		walk(base);
out:
	free(base);
	free(ovl);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t mode = 0;
	uint8_t *blob = NULL;

	if (size < 2 + FDT_V17_SIZE)
		return -1;
	mode = data[0];
	if (mode & 1) {
		size_t split = (size_t)data[1] * 16;

		if (split >= size - 2)
			return -1;
		/* Both halves need an FDT_V17_SIZE header: struct fdt_header. */
		if (fdt_check_header(data + 2) != 0 ||
		    fdt_totalsize(data + 2) > split)
			return -1;
		overlay(data + 2, size - 2, split);
		return 0;
	}
	data += 2;
	size -= 2;

	/* An exact-size copy so ASan sees reads that run past the blob. */
	blob = malloc(size);
	if (!blob)
		return 0;
	memcpy(blob, data, size);
	if (fdt_check_header(blob) != 0 || fdt_totalsize(blob) > size) {
		free(blob);
		return -1;
	}
	walk(blob);
	if (fdt_check_full(blob, size) == 0)
		rw_ops(blob, size);
	free(blob);
	return 0;
}
