/* QCBOR CBOR decoder (core/lib/qcbor), configured as OP-TEE builds it (no floating point). */
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void spiffy(const uint8_t *buf, size_t len, QCBORDecodeMode mode)
{
	QCBORDecodeContext dc;
	UsefulBufC s;
	int64_t i64 = 0;
	bool b = false;

	QCBORDecode_Init(&dc, (UsefulBufC){buf, len}, mode);
	QCBORDecode_EnterMap(&dc, NULL);
	QCBORDecode_GetInt64InMapN(&dc, 1, &i64);
	/*
	 * QCBOR's *ConvertAll* getters read a stack QCBORItem that is never filled when the decoder
	 * is already in an error state (sticky uLastError == QCBOR_ERR_UNEXPECTED_TYPE), so they are
	 * only called on an error-free decoder here; that upstream defect would otherwise crash
	 * every non-map input and hide everything behind it.
	 */
	if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS)
		QCBORDecode_GetInt64ConvertAllInMapN(&dc, 2, QCBOR_CONVERT_TYPE_XINT64 |
						     QCBOR_CONVERT_TYPE_BIG_NUM, &i64);
	QCBORDecode_GetTextStringInMapSZ(&dc, "name", &s);
	QCBORDecode_GetByteStringInMapN(&dc, -1, &s);
	QCBORDecode_GetBoolInMapSZ(&dc, "flag", &b);
	QCBORDecode_EnterArrayFromMapN(&dc, 3);
	QCBORDecode_GetInt64(&dc, &i64);
	QCBORDecode_GetTextString(&dc, &s);
	QCBORDecode_ExitArray(&dc);
	QCBORDecode_EnterBstrWrappedFromMapN(&dc, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, 4, &s);
	QCBORDecode_ExitBstrWrapped(&dc);
	QCBORDecode_ExitMap(&dc);
	(void)QCBORDecode_Finish(&dc);

	QCBORDecode_Init(&dc, (UsefulBufC){buf, len}, mode);
	QCBORDecode_EnterArray(&dc, NULL);
	if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS)
		QCBORDecode_GetInt64ConvertAll(&dc, QCBOR_CONVERT_TYPE_XINT64 |
					       QCBOR_CONVERT_TYPE_BIG_NUM |
					       QCBOR_CONVERT_TYPE_DECIMAL_FRACTION |
					       QCBOR_CONVERT_TYPE_BIGFLOAT, &i64);
	QCBORDecode_GetEpochDate(&dc, QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, &i64);
	QCBORDecode_GetTextString(&dc, &s);
	QCBORDecode_ExitArray(&dc);
	(void)QCBORDecode_Finish(&dc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	QCBORDecodeContext dc;
	QCBORItem item;
	QCBORDecodeMode mode;
	uint8_t *buf = NULL;
	uint64_t tags[8];
	int n = 0;

	if (size < 1)
		return -1;
	mode = (QCBORDecodeMode)(data[0] % 3);
	data++;
	size--;

	/* Exact-size copy so ASan sees reads past the encoded CBOR. */
	buf = malloc(size ? size : 1);
	if (!buf)
		return 0;
	memcpy(buf, data, size);

	QCBORDecode_Init(&dc, (UsefulBufC){buf, size}, mode);
	for (;;) {
		if (QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS)
			break;
		if (item.uDataType == QCBOR_TYPE_NONE || ++n > 100000)
			break;
	}
	(void)QCBORDecode_Finish(&dc);

	QCBORDecode_Init(&dc, (UsefulBufC){buf, size}, mode);
	for (n = 0; n < 100000; n++) {
		QCBORTagListOut tl = { 0, 8, tags };

		if (QCBORDecode_GetNextWithTags(&dc, &item, &tl) != QCBOR_SUCCESS)
			break;
		if (item.uDataType == QCBOR_TYPE_NONE)
			break;
	}

	spiffy(buf, size, mode);
	free(buf);
	return 0;
}
