#include "typedefs.h"
#include "identification.h"
#include "asn1_parser.h"

/**
 * ASN.1 definition of an X.509v3 x509_cert
 */
const asn1Object_t x509_certObjects[] = {
	{ 0, "x509",					ASN1_SEQUENCE,		ASN1_OBJ			}, /*  0 */
	{ 1,   "tbsCertificate",		ASN1_SEQUENCE,		ASN1_OBJ			}, /*  1 */
	{ 2,     "DEFAULT v1",			ASN1_CONTEXT_C_0,	ASN1_DEF			}, /*  2 */
	{ 3,       "version",			ASN1_INTEGER,		ASN1_BODY			}, /*  3 */
	{ 2,     "serialNumber",		ASN1_INTEGER,		ASN1_BODY			}, /*  4 */
	{ 2,     "signature",			ASN1_EOC,			ASN1_RAW			}, /*  5 */
	{ 2,     "issuer",				ASN1_SEQUENCE,		ASN1_OBJ			}, /*  6 */
	{ 2,     "validity",			ASN1_SEQUENCE,		ASN1_NONE			}, /*  7 */
	{ 3,       "notBefore",			ASN1_EOC,			ASN1_RAW			}, /*  8 */
	{ 3,       "notAfter",			ASN1_EOC,			ASN1_RAW			}, /*  9 */
	{ 2,     "subject",				ASN1_SEQUENCE,		ASN1_OBJ			}, /* 10 */
	{ 2,     "subjectPublicKeyInfo",ASN1_SEQUENCE,		ASN1_RAW			}, /* 11 */
	{ 2,     "issuerUniqueID",		ASN1_CONTEXT_C_1,	ASN1_OPT			}, /* 12 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 13 */
	{ 2,     "subjectUniqueID",		ASN1_CONTEXT_C_2,	ASN1_OPT			}, /* 14 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 15 */
	{ 2,     "optional extensions",	ASN1_CONTEXT_C_3,	ASN1_OPT			}, /* 16 */
	{ 3,       "extensions",		ASN1_SEQUENCE,		ASN1_LOOP			}, /* 17 */
	{ 4,         "extension",		ASN1_SEQUENCE,		ASN1_NONE			}, /* 18 */
	{ 5,           "extnID",		ASN1_OID,			ASN1_BODY			}, /* 19 */
	{ 5,           "critical",		ASN1_BOOLEAN,		ASN1_DEF|ASN1_BODY	}, /* 20 */
	{ 5,           "extnValue",		ASN1_OCTET_STRING,	ASN1_BODY			}, /* 21 */
	{ 3,       "end loop",			ASN1_EOC,			ASN1_END			}, /* 22 */
	{ 2,     "end opt",				ASN1_EOC,			ASN1_END			}, /* 23 */
	{ 1,   "signatureAlgorithm",	ASN1_EOC,			ASN1_RAW			}, /* 24 */
	{ 1,   "signatureValue",		ASN1_BIT_STRING,	ASN1_BODY			}, /* 25 */
	{ 0, "exit",					ASN1_EOC,			ASN1_EXIT			}
};

int
x509_to_str(void *cert, int cert_size, int tag,
	    STR *buf, int len)
{
	asn1_parser_t *parser;
	chunk_t object, blob;
	int objectID;

	blob = chunk_create(cert, cert_size);

	parser = asn1_parser_create(x509_certObjects, blob);
	parser->set_top_level(parser, 0);

	snprintf(buf, sizeof(buf), "MISPARSE");

	while (parser->iterate(parser, &objectID, &object)) {
		if (objectID == tag)
			dntoa(object, buf, len);
	}
	return 0;
}
