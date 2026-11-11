/*
 * mbedtls as vendored in lib/libmbedtls, built with OP-TEE's TA configuration
 * (mbedtls_config_uta.h): X.509 certificate parsing (PEM and DER), info and self-verification.
 */
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	mbedtls_x509_crt crt;
	char out[2048];
	uint32_t flags = 0;
	uint8_t *buf = malloc(size ? size : 1);

	if (!buf)
		return 0;
	memcpy(buf, data, size);

	mbedtls_x509_crt_init(&crt);
	if (mbedtls_x509_crt_parse(&crt, buf, size) == 0) {
		(void)mbedtls_x509_crt_info(out, sizeof(out), "", &crt);
		(void)mbedtls_x509_crt_check_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
		(void)mbedtls_x509_crt_check_extended_key_usage(&crt, MBEDTLS_OID_SERVER_AUTH,
								MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH));
		(void)mbedtls_x509_crt_verify(&crt, &crt, NULL, NULL, &flags, NULL, NULL);
	}
	mbedtls_x509_crt_free(&crt);

	mbedtls_x509_crt_init(&crt);
	if (mbedtls_x509_crt_parse_der(&crt, buf, size) == 0)
		(void)mbedtls_x509_crt_info(out, sizeof(out), "", &crt);
	mbedtls_x509_crt_free(&crt);

	free(buf);
	return 0;
}
