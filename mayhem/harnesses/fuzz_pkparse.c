/* mbedtls (OP-TEE TA configuration): public and private key parsing (DER and PEM). */
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int dummy_random(void *ctx, unsigned char *out, size_t len)
{
	uint32_t *ctr = ctx;
	size_t i = 0;

	for (i = 0; i < len; i++)
		out[i] = (unsigned char)((*ctr)++ * 0x9e3779b1u >> 24);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	mbedtls_pk_context pk;
	uint32_t ctr = 1;
	uint8_t *buf = NULL;
	uint8_t der[4096];

	if (size < 1)
		return -1;
	buf = malloc(size);
	if (!buf)
		return 0;
	memcpy(buf, data, size);

	mbedtls_pk_init(&pk);
	if (mbedtls_pk_parse_public_key(&pk, buf, size) == 0) {
		(void)mbedtls_pk_get_bitlen(&pk);
		(void)mbedtls_pk_get_name(&pk);
		(void)mbedtls_pk_write_pubkey_der(&pk, der, sizeof(der));
	}
	mbedtls_pk_free(&pk);

	mbedtls_pk_init(&pk);
	if (mbedtls_pk_parse_key(&pk, buf, size, NULL, 0, dummy_random, &ctr) == 0) {
		(void)mbedtls_pk_get_bitlen(&pk);
		(void)mbedtls_pk_check_pair(&pk, &pk, dummy_random, &ctr);
		(void)mbedtls_pk_write_key_der(&pk, der, sizeof(der));
	}
	mbedtls_pk_free(&pk);

	free(buf);
	return 0;
}
