/*
 * Copyright (C) 2009-2012 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "typedefs.h"
#include "identification.h"

#include "oid.h"
#include "asn1.h"

/**
 * coding of X.501 distinguished name
 */
typedef struct {
	const u_char *name;
	int oid;
	u_char type;
} x501rdn_t;

static const x501rdn_t x501rdns[] = {
	{"ND", 					OID_NAME_DISTINGUISHER,		ASN1_PRINTABLESTRING},
	{"UID", 				OID_PILOT_USERID,			ASN1_PRINTABLESTRING},
	{"DC", 					OID_PILOT_DOMAIN_COMPONENT, ASN1_PRINTABLESTRING},
	{"CN",					OID_COMMON_NAME,			ASN1_PRINTABLESTRING},
	{"S", 					OID_SURNAME,				ASN1_PRINTABLESTRING},
	{"SN", 					OID_SERIAL_NUMBER,			ASN1_PRINTABLESTRING},
	{"serialNumber", 		OID_SERIAL_NUMBER,			ASN1_PRINTABLESTRING},
	{"C", 					OID_COUNTRY,				ASN1_PRINTABLESTRING},
	{"L", 					OID_LOCALITY,				ASN1_PRINTABLESTRING},
	{"ST",					OID_STATE_OR_PROVINCE,		ASN1_PRINTABLESTRING},
	{"O", 					OID_ORGANIZATION,			ASN1_PRINTABLESTRING},
	{"OU", 					OID_ORGANIZATION_UNIT,		ASN1_PRINTABLESTRING},
	{"T", 					OID_TITLE,					ASN1_PRINTABLESTRING},
	{"D", 					OID_DESCRIPTION,			ASN1_PRINTABLESTRING},
	{"N", 					OID_NAME,					ASN1_PRINTABLESTRING},
	{"G", 					OID_GIVEN_NAME,				ASN1_PRINTABLESTRING},
	{"I", 					OID_INITIALS,				ASN1_PRINTABLESTRING},
	{"dnQualifier", 		OID_DN_QUALIFIER,			ASN1_PRINTABLESTRING},
	{"ID", 					OID_UNIQUE_IDENTIFIER,		ASN1_PRINTABLESTRING},
	{"EN", 					OID_EMPLOYEE_NUMBER,		ASN1_PRINTABLESTRING},
	{"employeeNumber",		OID_EMPLOYEE_NUMBER,		ASN1_PRINTABLESTRING},
	{"E",					OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"Email", 				OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"emailAddress",		OID_EMAIL_ADDRESS,			ASN1_IA5STRING},
	{"UN",					OID_UNSTRUCTURED_NAME,		ASN1_IA5STRING},
	{"unstructuredName",	OID_UNSTRUCTURED_NAME,		ASN1_IA5STRING},
	{"UA",					OID_UNSTRUCTURED_ADDRESS,	ASN1_PRINTABLESTRING},
	{"unstructuredAddress", OID_UNSTRUCTURED_ADDRESS,	ASN1_PRINTABLESTRING},
	{"TCGID", 				OID_TCGID,					ASN1_PRINTABLESTRING}
};

/**
 * maximum number of RDNs in atodn()
 */
#define RDN_MAX			20


typedef struct private_identification_t private_identification_t;

/**
 * Private data of an identification_t object.
 */
struct private_identification_t {
	/**
	 * Public interface.
	 */
	identification_t public;

	/**
	 * Encoded representation of this ID.
	 */
	chunk_t encoded;

	/**
	 * Type of this ID.
	 */
	id_type_t type;
};

/**
 * Enumerator over RDNs
 */
typedef struct {
	/* implements enumerator interface */
	enumerator_t public;
	/* next set to parse, if any */
	chunk_t sets;
	/* next sequence in set, if any */
	chunk_t seqs;
} rdn_enumerator_t;

METHOD(enumerator_t, rdn_enumerate, bool,
	rdn_enumerator_t *this, chunk_t *oid, u_char *type, chunk_t *data)
{
	chunk_t rdn;

	/* a DN contains one or more SET, each containing one or more SEQUENCES,
	 * each containing a OID/value RDN */
	if (!this->seqs.len)
	{
		/* no SEQUENCEs in current SET, parse next SET */
		if (asn1_unwrap(&this->sets, &this->seqs) != ASN1_SET)
		{
			return FALSE;
		}
	}
	if (asn1_unwrap(&this->seqs, &rdn) == ASN1_SEQUENCE &&
		asn1_unwrap(&rdn, oid) == ASN1_OID)
	{
		int t = asn1_unwrap(&rdn, data);

		if (t != ASN1_INVALID)
		{
			*type = t;
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * Create an enumerator over all RDNs (oid, string type, data) of a DN
 */
static enumerator_t* create_rdn_enumerator(chunk_t dn)
{
	rdn_enumerator_t *e;

	INIT(e,
		.public = {
			.enumerate = (void*)_rdn_enumerate,
			.destroy = (void*)free,
		},
	);

	/* a DN is a SEQUENCE, get the first SET of it */
	if (asn1_unwrap(&dn, &e->sets) == ASN1_SEQUENCE)
	{
		e->seqs = chunk_empty;
		return &e->public;
	}
	free(e);
	return enumerator_create_empty();
}

/**
 * Print a DN with all its RDN in a buffer to present it to the user
 */
void dntoa(chunk_t dn, STR *buf, size_t len)
{
	enumerator_t *e;
	chunk_t oid_data, data, printable;
	u_char type;
	int oid, written;
	bool finished = FALSE, empty = TRUE;

	e = create_rdn_enumerator(dn);
	while (e->enumerate(e, &oid_data, &type, &data))
	{
		empty = FALSE;

		oid = asn1_known_oid(oid_data);

		if (oid == OID_UNKNOWN)
		{
			written = snprintf(buf, len, "UNKNOWN-OID=");
		}
		else
		{
			written = snprintf(buf, len,"%" STRA "=", oid_names[oid].name);
		}
		if (written < 0 || written >= len)
		{
			break;
		}
		buf += written;
		len -= written;

		chunk_printable(data, &printable, '?');
		written = snprintf(buf, len, "%.*" STRA, (int)printable.len, printable.ptr);
		chunk_free(&printable);
		if (written < 0 || written >= len)
		{
			break;
		}
		buf += written;
		len -= written;

		if (data.ptr + data.len != dn.ptr + dn.len)
		{
			written = snprintf(buf, len, ", ");
			if (written < 0 || written >= len)
			{
				break;
			}
			buf += written;
			len -= written;
		}
		else
		{
			finished = TRUE;
			break;
		}
	}
	if (empty)
	{
		snprintf(buf, len, "");
	}
	else if (!finished)
	{
		snprintf(buf, len, "(invalid ID_DER_ASN1_DN)");
	}
	e->destroy(e);
}
