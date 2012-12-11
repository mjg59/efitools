/*
 * Copyright (C) 2008-2009 Tobias Brunner
 * Copyright (C) 2005-2008 Martin Willi
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

/**
 * @defgroup chunk chunk
 * @{ @ingroup libstrongswan
 */

#ifndef CHUNK_H_
#define CHUNK_H_

typedef struct chunk_t chunk_t;

/**
 * General purpose pointer/length abstraction.
 */
struct chunk_t {
	/** Pointer to start of data */
	u_char *ptr;
	/** Length of data in bytes */
	size_t len;
};

/**
 * A { NULL, 0 }-chunk handy for initialization.
 */
extern chunk_t chunk_empty;

/**
 * Create a new chunk pointing to "ptr" with length "len"
 */
static inline chunk_t chunk_create(u_char *ptr, size_t len)
{
	chunk_t chunk = {ptr, len};
	return chunk;
}

/**
 * Free contents of a chunk
 */
static inline void chunk_free(chunk_t *chunk)
{
	free(chunk->ptr);
	*chunk = chunk_empty;
}

/**
 * Overwrite the contents of a chunk and free it
 */
static inline void chunk_clear(chunk_t *chunk)
{
	if (chunk->ptr)
	{
		memset(chunk->ptr, 0, chunk->len);
		chunk_free(chunk);
	}
}

/**
 * Initialize a chunk using a char array
 */
#define chunk_from_chars(...) ((chunk_t){(char[]){__VA_ARGS__}, sizeof((char[]){__VA_ARGS__})})

/**
 * Initialize a chunk to point to a thing
 */
#define chunk_from_thing(thing) chunk_create((char*)&(thing), sizeof(thing))

/**
 * Allocate a chunk on the heap
 */
#define chunk_alloc(bytes) ({size_t x = (bytes); chunk_create(x ? malloc(x) : NULL, x);})

/**
 * Allocate a chunk on the stack
 */
#define chunk_alloca(bytes) ({size_t x = (bytes); chunk_create(x ? alloca(x) : NULL, x);})

/**
 * Clone a chunk on heap
 */
#define chunk_clone(chunk) ({chunk_t x = (chunk); chunk_create_clone(x.len ? malloc(x.len) : NULL, x);})

/**
 * Skip n bytes in chunk (forward pointer, shorten length)
 */
static inline chunk_t chunk_skip(chunk_t chunk, size_t bytes)
{
	if (chunk.len > bytes)
	{
		chunk.ptr += bytes;
		chunk.len -= bytes;
		return chunk;
	}
	return chunk_empty;
}

/**
 * Skip a leading zero-valued byte
 */
static inline chunk_t chunk_skip_zero(chunk_t chunk)
{
	if (chunk.len > 1 && *chunk.ptr == 0x00)
	{
		chunk.ptr++;
		chunk.len--;
	}
	return chunk;
}


/**
 *  Compare two chunks, returns zero if a equals b
 *  or negative/positive if a is small/greater than b
 */
int chunk_compare(chunk_t a, chunk_t b);

/**
 * Compare two chunks for equality,
 * NULL chunks are never equal.
 */
static inline bool chunk_equals(chunk_t a, chunk_t b)
{
	return a.ptr != NULL  && b.ptr != NULL &&
			a.len == b.len && memeq(a.ptr, b.ptr, a.len);
}

/**
 * Compare two chunks (given as pointers) for equality (useful as callback),
 * NULL chunks are never equal.
 */
static inline bool chunk_equals_ptr(chunk_t *a, chunk_t *b)
{
	return a != NULL && b != NULL && chunk_equals(*a, *b);
}

/**
 * Check if a chunk has printable characters only.
 *
 * If sane is given, chunk is cloned into sane and all non printable characters
 * get replaced by "replace".
 *
 * @param chunk			chunk to check for printability
 * @param sane			pointer where sane version is allocated, or NULL
 * @param replace		character to use for replaceing unprintable characters
 * @return				TRUE if all characters in chunk are printable
 */
bool chunk_printable(chunk_t chunk, chunk_t *sane, char replace);

#endif
