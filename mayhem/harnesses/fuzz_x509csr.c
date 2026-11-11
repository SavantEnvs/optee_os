/* mbedtls (OP-TEE TA configuration): X.509 certificate signing request parsing, PEM and DER. */
#include <mbedtls/x509_csr.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	mbedtls_x509_csr csr;
	char out[2048];
	uint8_t *buf = malloc(size ? size : 1);

	if (!buf)
		return 0;
	memcpy(buf, data, size);

	mbedtls_x509_csr_init(&csr);
	if (mbedtls_x509_csr_parse(&csr, buf, size) == 0)
		(void)mbedtls_x509_csr_info(out, sizeof(out), "", &csr);
	mbedtls_x509_csr_free(&csr);

	mbedtls_x509_csr_init(&csr);
	if (mbedtls_x509_csr_parse_der(&csr, buf, size) == 0)
		(void)mbedtls_x509_csr_info(out, sizeof(out), "", &csr);
	mbedtls_x509_csr_free(&csr);

	free(buf);
	return 0;
}
