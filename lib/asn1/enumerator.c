/*
 * Copyright (C) 2008 Tobias Brunner
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

#include "typedefs.h"
#include "enumerator.h"

/**
 * Implementation of enumerator_create_empty().enumerate
 */
static bool enumerate_empty(enumerator_t *enumerator, ...)
{
	return FALSE;
}

/**
 * See header
 */
enumerator_t* enumerator_create_empty(void)
{
	enumerator_t *this = malloc_thing(enumerator_t);
	this->enumerate = enumerate_empty;
	this->destroy = (void*)free;
	return this;
}

/**
 * enumerator for nested enumerations
 */
typedef struct {
	/* implements enumerator_t */
	enumerator_t public;
	/* outer enumerator */
	enumerator_t *outer;
	/* inner enumerator */
	enumerator_t *inner;
	/* constructor for inner enumerator */
	enumerator_t *(*create_inner)(void *outer, void *data);
	/* data to pass to constructor above */
	void *data;
	/* destructor for data */
	void (*destroy_data)(void *data);
} nested_enumerator_t;


/**
 * Implementation of enumerator_create_nested().enumerate()
 */
static bool enumerate_nested(nested_enumerator_t *this, void *v1, void *v2,
							 void *v3, void *v4, void *v5)
{
	while (TRUE)
	{
		while (this->inner == NULL)
		{
			void *outer;

			if (!this->outer->enumerate(this->outer, &outer))
			{
				return FALSE;
			}
			this->inner = this->create_inner(outer, this->data);
		}
		if (this->inner->enumerate(this->inner, v1, v2, v3, v4, v5))
		{
			return TRUE;
		}
		this->inner->destroy(this->inner);
		this->inner = NULL;
	}
}

/**
 * Implementation of enumerator_create_nested().destroy()
 **/
static void destroy_nested(nested_enumerator_t *this)
{
	if (this->destroy_data)
	{
		this->destroy_data(this->data);
	}
	DESTROY_IF(this->inner);
	this->outer->destroy(this->outer);
	free(this);
}

/**
 * See header
 */
enumerator_t *enumerator_create_nested(enumerator_t *outer,
					enumerator_t *(inner_constructor)(void *outer, void *data),
					void *data, void (*destroy_data)(void *data))
{
	nested_enumerator_t *enumerator = malloc_thing(nested_enumerator_t);

	enumerator->public.enumerate = (void*)enumerate_nested;
	enumerator->public.destroy = (void*)destroy_nested;
	enumerator->outer = outer;
	enumerator->inner = NULL;
	enumerator->create_inner = (void*)inner_constructor;
	enumerator->data = data;
	enumerator->destroy_data = destroy_data;

	return &enumerator->public;
}

/**
 * enumerator for filtered enumerator
 */
typedef struct {
	enumerator_t public;
	enumerator_t *unfiltered;
	void *data;
	bool (*filter)(void *data, ...);
	void (*destructor)(void *data);
} filter_enumerator_t;

/**
 * Implementation of enumerator_create_filter().destroy
 */
static void destroy_filter(filter_enumerator_t *this)
{
	if (this->destructor)
	{
		this->destructor(this->data);
	}
	this->unfiltered->destroy(this->unfiltered);
	free(this);
}

/**
 * Implementation of enumerator_create_filter().enumerate
 */
static bool enumerate_filter(filter_enumerator_t *this, void *o1, void *o2,
							 void *o3, void *o4, void *o5)
{
	void *i1, *i2, *i3, *i4, *i5;

	while (this->unfiltered->enumerate(this->unfiltered, &i1, &i2, &i3, &i4, &i5))
	{
		if (this->filter(this->data, &i1, o1, &i2, o2, &i3, o3, &i4, o4, &i5, o5))
		{
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * see header
 */
enumerator_t *enumerator_create_filter(enumerator_t *unfiltered,
									   bool (*filter)(void *data, ...),
									   void *data, void (*destructor)(void *data))
{
	filter_enumerator_t *this = malloc_thing(filter_enumerator_t);

	this->public.enumerate = (void*)enumerate_filter;
	this->public.destroy = (void*)destroy_filter;
	this->unfiltered = unfiltered;
	this->filter = filter;
	this->data = data;
	this->destructor = destructor;

	return &this->public;
}

/**
 * enumerator for cleaner enumerator
 */
typedef struct {
	enumerator_t public;
	enumerator_t *wrapped;
	void (*cleanup)(void *data);
	void *data;
} cleaner_enumerator_t;

/**
 * Implementation of enumerator_create_cleanup().destroy
 */
static void destroy_cleaner(cleaner_enumerator_t *this)
{
	this->cleanup(this->data);
	this->wrapped->destroy(this->wrapped);
	free(this);
}

/**
 * Implementation of enumerator_create_cleaner().enumerate
 */
static bool enumerate_cleaner(cleaner_enumerator_t *this, void *v1, void *v2,
							  void *v3, void *v4, void *v5)
{
	return this->wrapped->enumerate(this->wrapped, v1, v2, v3, v4, v5);
}

/**
 * see header
 */
enumerator_t *enumerator_create_cleaner(enumerator_t *wrapped,
										void (*cleanup)(void *data), void *data)
{
	cleaner_enumerator_t *this = malloc_thing(cleaner_enumerator_t);

	this->public.enumerate = (void*)enumerate_cleaner;
	this->public.destroy = (void*)destroy_cleaner;
	this->wrapped = wrapped;
	this->cleanup = cleanup;
	this->data = data;

	return &this->public;
}

/**
 * enumerator for single enumerator
 */
typedef struct {
	enumerator_t public;
	void *item;
	void (*cleanup)(void *item);
	bool done;
} single_enumerator_t;

/**
 * Implementation of enumerator_create_single().destroy
 */
static void destroy_single(single_enumerator_t *this)
{
	if (this->cleanup)
	{
		this->cleanup(this->item);
	}
	free(this);
}

/**
 * Implementation of enumerator_create_single().enumerate
 */
static bool enumerate_single(single_enumerator_t *this, void **item)
{
	if (this->done)
	{
		return FALSE;
	}
	*item = this->item;
	this->done = TRUE;
	return TRUE;
}

/**
 * see header
 */
enumerator_t *enumerator_create_single(void *item, void (*cleanup)(void *item))
{
	single_enumerator_t *this = malloc_thing(single_enumerator_t);

	this->public.enumerate = (void*)enumerate_single;
	this->public.destroy = (void*)destroy_single;
	this->item = item;
	this->cleanup = cleanup;
	this->done = FALSE;

	return &this->public;
}

