/*
 * Copyright (C) 2006 Martin Will
 * Copyright (C) 2000-2008 Andreas Steffen
 *
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
#include "enumerator.h"
#include "chunk.h"
#include "oid.h"
#include "asn1.h"
#include "asn1_parser.h"

/*
 * Defined in header.
 */
int asn1_known_oid(chunk_t object)
{
	int oid = 0;

	while (object.len)
	{
		if (oid_names[oid].octet == *object.ptr)
		{
			if (--object.len == 0 || oid_names[oid].down == 0)
			{
				return oid;		  /* found terminal symbol */
			}
			else
			{
				object.ptr++; oid++; /* advance to next hex octet */
			}
		}
		else
		{
			if (oid_names[oid].next)
			{
				oid = oid_names[oid].next;
			}
			else
			{
				return OID_UNKNOWN;
			}
		}
	}
	return -1;
}

/*
 * Defined in header.
 */
chunk_t asn1_build_known_oid(int n)
{
	chunk_t oid;
	int i;

	if (n < 0 || n >= OID_MAX)
	{
		return chunk_empty;
	}

	i = oid_names[n].level + 1;
	oid = chunk_alloc(2 + i);
	oid.ptr[0] = ASN1_OID;
	oid.ptr[1] = i;

	do
	{
		if (oid_names[n].level >= i)
		{
			n--;
			continue;
		}
		oid.ptr[--i + 2] = oid_names[n--].octet;
	}
	while (i > 0);

	return oid;
}

/*
 * Defined in header.
 */
size_t asn1_length(chunk_t *blob)
{
	u_char n;
	size_t len;

	if (blob->len < 2)
	{
		DBG1("insufficient number of octets to parse ASN.1 length");
		return ASN1_INVALID_LENGTH;
	}

	/* read length field, skip tag and length */
	n = blob->ptr[1];
	blob->ptr += 2;
	blob->len -= 2;

	if ((n & 0x80) == 0)
	{	/* single length octet */
		if (n > blob->len)
		{
			DBG1("length is larger than remaining blob size");
			return ASN1_INVALID_LENGTH;
		}
		return n;
	}

	/* composite length, determine number of length octets */
	n &= 0x7f;

	if (n == 0 || n > blob->len)
	{
		DBG1("number of length octets invalid");
		return ASN1_INVALID_LENGTH;
	}

	if (n > sizeof(len))
	{
		DBG1("number of length octets is larger than limit of"
			 " %d octets", (int)sizeof(len));
		return ASN1_INVALID_LENGTH;
	}

	len = 0;

	while (n-- > 0)
	{
		len = 256*len + *blob->ptr++;
		blob->len--;
	}
	if (len > blob->len)
	{
		DBG1("length is larger than remaining blob size");
		return ASN1_INVALID_LENGTH;
	}
	return len;
}

/*
 * See header.
 */
int asn1_unwrap(chunk_t *blob, chunk_t *inner)
{
	chunk_t res;
	u_char len;
	int type;

	if (blob->len < 2)
	{
		return ASN1_INVALID;
	}
	type = blob->ptr[0];
	len = blob->ptr[1];
	*blob = chunk_skip(*blob, 2);

	if ((len & 0x80) == 0)
	{	/* single length octet */
		res.len = len;
	}
	else
	{	/* composite length, determine number of length octets */
		len &= 0x7f;
		if (len == 0 || len > sizeof(res.len))
		{
			return ASN1_INVALID;
		}
		res.len = 0;
		while (len-- > 0)
		{
			res.len = 256 * res.len + blob->ptr[0];
			*blob = chunk_skip(*blob, 1);
		}
	}
	if (res.len > blob->len)
	{
		return ASN1_INVALID;
	}
	res.ptr = blob->ptr;
	*blob = chunk_skip(*blob, res.len);
	/* updating inner not before we are finished allows a caller to pass
	 * blob = inner */
	*inner = res;
	return type;
}
