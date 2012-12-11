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

/**
 * @defgroup asn1i asn1
 * @{ @ingroup asn1
 */

#ifndef ASN1_H_
#define ASN1_H_

/**
 * Definition of some primitive ASN1 types
 */
typedef enum {
	ASN1_EOC =				0x00,
	ASN1_BOOLEAN =			0x01,
	ASN1_INTEGER =			0x02,
	ASN1_BIT_STRING =		0x03,
	ASN1_OCTET_STRING =		0x04,
	ASN1_NULL =				0x05,
	ASN1_OID =				0x06,
	ASN1_ENUMERATED =		0x0A,
	ASN1_UTF8STRING =		0x0C,
	ASN1_NUMERICSTRING =	0x12,
	ASN1_PRINTABLESTRING =	0x13,
	ASN1_T61STRING =		0x14,
	ASN1_VIDEOTEXSTRING =	0x15,
	ASN1_IA5STRING =		0x16,
	ASN1_UTCTIME =			0x17,
	ASN1_GENERALIZEDTIME =	0x18,
	ASN1_GRAPHICSTRING =	0x19,
	ASN1_VISIBLESTRING =	0x1A,
	ASN1_GENERALSTRING =	0x1B,
	ASN1_UNIVERSALSTRING =	0x1C,
	ASN1_BMPSTRING =		0x1E,

	ASN1_CONSTRUCTED =		0x20,

	ASN1_SEQUENCE =			0x30,
	ASN1_SET =				0x31,

	ASN1_CONTEXT_S_0 =		0x80,
	ASN1_CONTEXT_S_1 =		0x81,
	ASN1_CONTEXT_S_2 =		0x82,
	ASN1_CONTEXT_S_3 =		0x83,
	ASN1_CONTEXT_S_4 =		0x84,
	ASN1_CONTEXT_S_5 =		0x85,
	ASN1_CONTEXT_S_6 =		0x86,
	ASN1_CONTEXT_S_7 =		0x87,
	ASN1_CONTEXT_S_8 =		0x88,

	ASN1_CONTEXT_C_0 =		0xA0,
	ASN1_CONTEXT_C_1 =		0xA1,
	ASN1_CONTEXT_C_2 =		0xA2,
	ASN1_CONTEXT_C_3 =		0xA3,
	ASN1_CONTEXT_C_4 =		0xA4,
	ASN1_CONTEXT_C_5 =		0xA5,

	ASN1_INVALID =			0x100,
} asn1_t;

#define ASN1_INVALID_LENGTH	0xffffffff

/** Some ASN.1 analysis functions */

/**
 * Converts an ASN.1 OID into a known OID index
 *
 * @param object	body of an OID
 * @return			index into the oid_names[] table or OID_UNKNOWN
 */
int asn1_known_oid(chunk_t object);

/**
 * Converts a known OID index to an ASN.1 OID
 *
 * @param n			index into the oid_names[] table
 * @return			allocated OID chunk, chunk_empty if index out of range
 */
chunk_t asn1_build_known_oid(int n);

/**
 * Returns the length of an ASN.1 object
 * The blob pointer is advanced past the tag length fields
 *
 * @param blob		pointer to an ASN.1 coded blob
 * @return			length of ASN.1 object
 */
size_t asn1_length(chunk_t *blob);

/**
 * Unwrap the inner content of an ASN.1 type/length wrapped object.
 *
 * @param blob		blob to parse header from, moved behind parsed content
 * @param content	inner content
 * @return			parsed type, ASN1_INVALID if length parsing failed
 */
int asn1_unwrap(chunk_t *blob, chunk_t *content);

#endif /** ASN1_H_ @}*/
