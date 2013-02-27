
#define certlist_for_each_certentry(cl, cl_init, s, s_init)		\
	for (cl = (EFI_SIGNATURE_LIST *)(cl_init), s = (s_init);	\
		s > 0 && s >= cl->SignatureListSize;			\
		s -= cl->SignatureListSize,				\
		cl = (EFI_SIGNATURE_LIST *) ((UINT8 *)cl + cl->SignatureListSize))

/*
 * Warning: this assumes (cl)->SignatureHeaderSize is zero.  It is for all
 * the signatures we process (X509, RSA2048, SHA256)
 */
#define certentry_for_each_cert(c, cl)	\
  for (c = (EFI_SIGNATURE_DATA *)((UINT8 *) (cl) + sizeof(EFI_SIGNATURE_LIST) + (cl)->SignatureHeaderSize); \
	(UINT8 *)c < ((UINT8 *)(cl)) + (cl)->SignatureListSize; \
	c = (EFI_SIGNATURE_DATA *)((UINT8 *)c + (cl)->SignatureSize))

