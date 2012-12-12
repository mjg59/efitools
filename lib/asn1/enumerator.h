/*
 * Copyright (C) 2007 Martin Willi
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
 * @defgroup enumerator enumerator
 * @{ @ingroup utils
 */

#ifndef ENUMERATOR_H_
#define ENUMERATOR_H_

typedef struct enumerator_t enumerator_t;

/**
 * Enumerator interface, allows enumeration over collections.
 */
struct enumerator_t {

	/**
	 * Enumerate collection.
	 *
	 * The enumerate function takes a variable argument list containing
	 * pointers where the enumerated values get written.
	 *
	 * @param ...	variable list of enumerated items, implementation dependent
	 * @return		TRUE if pointers returned
	 */
	bool (*enumerate)(enumerator_t *this, ...);

	/**
	 * Destroy a enumerator instance.
	 */
	void (*destroy)(enumerator_t *this);
};

/**
 * Create an enumerator which enumerates over nothing
 *
 * @return			an enumerator over no values
 */
enumerator_t* enumerator_create_empty();

#endif /** ENUMERATOR_H_ @}*/
