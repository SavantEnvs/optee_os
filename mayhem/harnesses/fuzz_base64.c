/* lib/libutils/ext/base64.c: decode arbitrary text, then check the encode/decode round trip. */
#include <base64.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t dlen = size;
	size_t elen = 0;
	char *txt = malloc(size ? size : 1);
	uint8_t *dec = malloc(size ? size : 1);
	char *enc = NULL;
	uint8_t *back = NULL;

	if (!txt || !dec)
		goto out;
	memcpy(txt, data, size);
	if (base64_dec(txt, size, dec, &dlen)) {
		elen = base64_enc_len(dlen);
		enc = malloc(elen);
		back = malloc(dlen ? dlen : 1);
		if (!enc || !back)
			goto out;
		if (!base64_enc(dec, dlen, enc, &elen))
			abort();
		size_t blen = dlen;

		if (!base64_dec(enc, elen - 1, back, &blen) || blen != dlen ||
		    memcmp(back, dec, dlen))
			abort();
	}
out:
	free(txt);
	free(dec);
	free(enc);
	free(back);
	return 0;
}
