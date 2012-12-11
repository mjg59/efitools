#ifndef STR
#define STR CHAR16
#endif

#define X509_OBJ_TBS_CERTIFICATE				 1
#define X509_OBJ_VERSION						 3
#define X509_OBJ_SERIAL_NUMBER					 4
#define X509_OBJ_SIG_ALG						 5
#define X509_OBJ_ISSUER							 6
#define X509_OBJ_NOT_BEFORE						 8
#define X509_OBJ_NOT_AFTER						 9
#define X509_OBJ_SUBJECT						10
#define X509_OBJ_SUBJECT_PUBLIC_KEY_INFO		11
#define X509_OBJ_OPTIONAL_EXTENSIONS			16
#define X509_OBJ_EXTN_ID						19
#define X509_OBJ_CRITICAL						20
#define X509_OBJ_EXTN_VALUE						21
#define X509_OBJ_ALGORITHM						24
#define X509_OBJ_SIGNATURE						25

int
x509_to_str(void *cert, int cert_size, int tag,
	    STR *buf, int len);
