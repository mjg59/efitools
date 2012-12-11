/*
 * Copyright (C) 2008-2009 Tobias Brunner
 * Copyright (C) 2005-2006 Martin Willi
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
#include "chunk.h"

/**
 * Empty chunk.
 */
chunk_t chunk_empty = { NULL, 0 };

 /**
  * Described in header.
  */
chunk_t chunk_create_clone(u_char *ptr, chunk_t chunk)
{
	chunk_t clone = chunk_empty;

	if (chunk.ptr && chunk.len > 0)
	{
		clone.ptr = ptr;
		clone.len = chunk.len;
		memcpy(clone.ptr, chunk.ptr, chunk.len);
	}

	return clone;
}

/**
 * Described in header.
 */
int chunk_compare(chunk_t a, chunk_t b)
{
	int compare_len = a.len - b.len;
	int len = (compare_len < 0)? a.len : b.len;

	if (compare_len != 0 || len == 0)
	{
		return compare_len;
	}
	return memcmp(a.ptr, b.ptr, len);
};


/**
 * Remove non-printable characters from a chunk.
 */
bool chunk_printable(chunk_t chunk, chunk_t *sane, char replace)
{
	bool printable = TRUE;
	int i;

	if (sane)
	{
		*sane = chunk_clone(chunk);
	}
	for (i = 0; i < chunk.len; i++)
	{
		if (!isprint(chunk.ptr[i]))
		{
			if (sane)
			{
				sane->ptr[i] = replace;
			}
			printable = FALSE;
		}
	}
	return printable;
}
