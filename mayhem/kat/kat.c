/*
 * Known-answer probe for the libraries the harnesses fuzz. Built by build.sh with the project's
 * normal flags (no sanitizers) and dynamically linked, so the oracle in test.sh is affected by
 * the sabotage check. Every subcommand prints fixed, expected lines.
 */
#include <base64.h>
#include <libfdt.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static const char ec_crt_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIB7TCCAZOgAwIBAgIUWV3h3MA1N+dDVf1XWr92FL6dko8wCgYIKoZIzj0EAwIw\n"
	"NTELMAkGA1UEBhMCU0UxDzANBgNVBAoMBk9QLVRFRTEVMBMGA1UEAwwMb3B0ZWUt\n"
	"bWF5aGVtMB4XDTI2MTExMTA4MDAzNloXDTM2MTEwODA4MDAzNlowNTELMAkGA1UE\n"
	"BhMCU0UxDzANBgNVBAoMBk9QLVRFRTEVMBMGA1UEAwwMb3B0ZWUtbWF5aGVtMFkw\n"
	"EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET2/+QWC3yN7RB1tCKdZR1BXQDFaSY0Bn\n"
	"hwX4qSTmXPMxVJbdYWm6BslaFTCkhx2hXVexqjQDtcM8AUgVx4w25KOBgDB+MB0G\n"
	"A1UdDgQWBBQ6fRUJ+oXRUEn1eUin0ZpZzYgIJzAfBgNVHSMEGDAWgBQ6fRUJ+oXR\n"
	"UEn1eUin0ZpZzYgIJzAPBgNVHRMBAf8EBTADAQH/MAsGA1UdDwQEAwIHgDAeBgNV\n"
	"HREEFzAVgg1vcHRlZS5leGFtcGxlhwQKAAABMAoGCCqGSM49BAMCA0gAMEUCIQDi\n"
	"fd/sCTmZ7V0RHPmweTOxgUBhJUE6aCPvZGr45h6uKAIgbP/4PH3FDRK7MYuKb3BG\n"
	"xB737lczGN5t2BztWWRjOx0=\n"
	"-----END CERTIFICATE-----\n";

static const char ec_pub_pem[] =
	"-----BEGIN PUBLIC KEY-----\n"
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET2/+QWC3yN7RB1tCKdZR1BXQDFaS\n"
	"Y0BnhwX4qSTmXPMxVJbdYWm6BslaFTCkhx2hXVexqjQDtcM8AUgVx4w25A==\n"
	"-----END PUBLIC KEY-----\n";

static int kat_fdt(void)
{
	uint8_t buf[512];
	const uint32_t *reg = NULL;
	const char *compat = NULL;
	int len = 0;
	int cpus = 0;

	if (fdt_create(buf, sizeof(buf)) || fdt_finish_reservemap(buf) ||
	    fdt_begin_node(buf, "") || fdt_property_string(buf, "compatible", "foo,bar") ||
	    fdt_begin_node(buf, "cpus") || fdt_property_u32(buf, "reg", 4) ||
	    fdt_end_node(buf) || fdt_end_node(buf) || fdt_finish(buf))
		return 1;
	if (fdt_check_full(buf, sizeof(buf)))
		return 1;
	cpus = fdt_path_offset(buf, "/cpus");
	reg = fdt_getprop(buf, cpus, "reg", &len);
	compat = fdt_getprop(buf, 0, "compatible", &len);
	if (!reg || !compat)
		return 1;
	printf("fdt: cpus-reg=%u compatible=%s match=%d\n", fdt32_to_cpu(*reg), compat,
	       fdt_node_check_compatible(buf, 0, "foo,bar"));
	return 0;
}

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

static int kat_inflate(void)
{
	static const unsigned char z[] = { 0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57,
					   0x28, 0xcf, 0x2f, 0xca, 0x49, 0x01, 0x00, 0x1a,
					   0x0b, 0x04, 0x5d };
	unsigned char out[64] = { 0 };
	z_stream s;
	int r = 0;

	memset(&s, 0, sizeof(s));
	s.zalloc = zalloc_cb;
	s.zfree = zfree_cb;
	if (inflateInit(&s) != Z_OK)
		return 1;
	s.next_in = (unsigned char *)z;
	s.avail_in = sizeof(z);
	s.next_out = out;
	s.avail_out = sizeof(out) - 1;
	r = inflate(&s, Z_FINISH);
	printf("inflate: rc=%d out=%s adler=%lu\n", r, out, (unsigned long)s.adler);
	inflateEnd(&s);
	return 0;
}

static int kat_base64(void)
{
	uint8_t dec[16] = { 0 };
	char enc[32] = { 0 };
	size_t dlen = sizeof(dec) - 1;
	size_t elen = sizeof(enc);
	bool a = base64_dec("Zm9vYmFy", 8, dec, &dlen);
	bool b = base64_enc("foobar!", 7, enc, &elen);

	printf("base64: dec=%d %s enc=%d %s\n", a, dec, b, enc);
	return 0;
}

static int kat_qcbor(void)
{
	static const uint8_t cbor[] = { 0xa2, 0x01, 0x18, 0x2a, 0x62, 0x68, 0x69,
					0x83, 0x01, 0x02, 0x03 };
	uint8_t outbuf[32];
	QCBORDecodeContext dc;
	QCBOREncodeContext ec;
	UsefulBufC enc;
	int64_t v = 0;
	int64_t sum = 0;
	int64_t e = 0;
	size_t n = 0;

	QCBORDecode_Init(&dc, (UsefulBufC){ cbor, sizeof(cbor) }, QCBOR_DECODE_MODE_NORMAL);
	QCBORDecode_EnterMap(&dc, NULL);
	QCBORDecode_GetInt64InMapN(&dc, 1, &v);
	QCBORDecode_EnterArrayFromMapSZ(&dc, "hi");
	for (n = 0; n < 3; n++) {
		QCBORDecode_GetInt64(&dc, &e);
		sum += e;
	}
	QCBORDecode_ExitArray(&dc);
	QCBORDecode_ExitMap(&dc);
	printf("qcbor: dec-err=%d v=%d sum=%d\n", (int)QCBORDecode_Finish(&dc), (int)v, (int)sum);

	QCBOREncode_Init(&ec, (UsefulBuf){ outbuf, sizeof(outbuf) });
	QCBOREncode_OpenMap(&ec);
	QCBOREncode_AddInt64ToMapN(&ec, 1, 42);
	QCBOREncode_OpenArrayInMap(&ec, "hi");
	QCBOREncode_AddInt64(&ec, 1);
	QCBOREncode_AddInt64(&ec, 2);
	QCBOREncode_AddInt64(&ec, 3);
	QCBOREncode_CloseArray(&ec);
	QCBOREncode_CloseMap(&ec);
	if (QCBOREncode_Finish(&ec, &enc))
		return 1;
	printf("qcbor: enc=");
	for (n = 0; n < enc.len; n++)
		printf("%02x", ((const uint8_t *)enc.ptr)[n]);
	printf("\n");
	return 0;
}

static int kat_x509(void)
{
	mbedtls_x509_crt crt;
	mbedtls_pk_context pk;
	char dn[128] = { 0 };
	uint32_t flags = 0xffffffff;
	int r = 0;
	int v = 0;

	mbedtls_x509_crt_init(&crt);
	r = mbedtls_x509_crt_parse(&crt, (const unsigned char *)ec_crt_pem, sizeof(ec_crt_pem));
	if (r)
		return 1;
	mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.subject);
	v = mbedtls_x509_crt_verify(&crt, &crt, NULL, NULL, &flags, NULL, NULL);
	printf("x509: subject=%s version=%d bits=%d pk=%s selfverify=%d flags=%u\n", dn,
	       crt.version, (int)mbedtls_pk_get_bitlen(&crt.pk), mbedtls_pk_get_name(&crt.pk),
	       v, (unsigned)flags);
	mbedtls_x509_crt_free(&crt);

	mbedtls_pk_init(&pk);
	r = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)ec_pub_pem,
					sizeof(ec_pub_pem));
	printf("pk: parse=%d bits=%d name=%s\n", r, (int)mbedtls_pk_get_bitlen(&pk),
	       mbedtls_pk_get_name(&pk));
	mbedtls_pk_free(&pk);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	if (!strcmp(argv[1], "fdt"))
		return kat_fdt();
	if (!strcmp(argv[1], "inflate"))
		return kat_inflate();
	if (!strcmp(argv[1], "base64"))
		return kat_base64();
	if (!strcmp(argv[1], "qcbor"))
		return kat_qcbor();
	if (!strcmp(argv[1], "x509"))
		return kat_x509();
	return 2;
}
