/*
 * OP-TEE's zlib (core/lib/zlib): inflate-only. data[0] picks the window/format
 * (zlib, raw, gzip, auto-detect), data[1] the input chunk size, the rest is the stream.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static voidpf zalloc_cb(voidpf opaque, uInt items, uInt size)
{
	(void)opaque;
	return calloc(items, size);
}

static void zfree_cb(voidpf opaque, voidpf ptr)
{
	(void)opaque;
	free(ptr);
}

#define OUT_CHUNK 4096
#define OUT_CAP (8u * 1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const int wbits[4] = { 15, -15, 31, 47 };
	unsigned char out[OUT_CHUNK];
	z_stream strm;
	uint8_t *in = NULL;
	size_t chunk = 0;
	size_t off = 0;
	size_t total = 0;
	int ret = Z_OK;

	if (size < 2)
		return -1;
	chunk = (size_t)data[1] + 1;
	memset(&strm, 0, sizeof(strm));
	strm.zalloc = zalloc_cb;
	strm.zfree = zfree_cb;
	if (inflateInit2(&strm, wbits[data[0] & 3]) != Z_OK)
		return 0;
	data += 2;
	size -= 2;

	/* Exact-size copy so ASan sees reads past the end of the stream. */
	in = malloc(size ? size : 1);
	if (!in) {
		inflateEnd(&strm);
		return 0;
	}
	memcpy(in, data, size);

	while (ret == Z_OK || ret == Z_BUF_ERROR) {
		size_t n = size - off < chunk ? size - off : chunk;

		if (n == 0 && strm.avail_in == 0)
			break;
		if (strm.avail_in == 0) {
			strm.next_in = in + off;
			strm.avail_in = (uInt)n;
			off += n;
		}
		strm.next_out = out;
		strm.avail_out = sizeof(out);
		ret = inflate(&strm, Z_NO_FLUSH);
		total += sizeof(out) - strm.avail_out;
		if (total > OUT_CAP)
			break;
	}
	inflateEnd(&strm);
	free(in);
	return 0;
}
