#ifdef BUILD_EFI
#include <efi.h>
#include <efilib.h>

#define malloc(x) AllocatePool(x)
#define free FreePool
#define strcmp(x,y) StrCmp(x,y)
#define memset(m,c,l) ZeroMem(m,l)
#define memcmp(x,y,z) strncmpa(x,y,z)
#define isprint(x) (1)
#define snprintf(s, l, f...) SPrint(s, l, L ## f)

/* STR is the native string and STRA is how to printf and ASCII string */
#define STR CHAR16
#define STRA "a"
#define size_t UINTN

static inline void
MEMCPY(void *dest, void *src, size_t n)
{
	UINTN i;
	char *d = dest, *s = src;

	for (i = 0; i < n; i++)
		d[i] = s[i];
}

#define memcpy MEMCPY

typedef unsigned char u_char;

#else

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <time.h>

#define STR char
#define STRA "s"

#define FALSE  0
#define TRUE 1

#endif

typedef unsigned char bool;
typedef unsigned int u_int;

#define DBG1(s...)
#define DBG2(s...)

/**
 * Method declaration/definition macro, providing private and public interface.
 *
 * Defines a method name with this as first parameter and a return value ret,
 * and an alias for this method with a _ prefix, having the this argument
 * safely casted to the public interface iface.
 * _name is provided a function pointer, but will get optimized out by GCC.
 */
#define METHOD(iface, name, ret, this, ...) \
        static ret name(union {iface *_public; this;} \
        __attribute__((transparent_union)), ##__VA_ARGS__); \
        static typeof(name) *_##name = (typeof(name)*)name; \
        static ret name(this, ##__VA_ARGS__)

/**
 * Object allocation/initialization macro, using designated initializer.
 */
#define INIT(this, ...) { (this) = malloc(sizeof(*(this))); \
                                                   *(this) = (typeof(*(this))){ __VA_ARGS__ }; }

/**
 * Macro to allocate a sized type.
 */
#define malloc_thing(thing) ((thing*)malloc(sizeof(thing)))
/**
 * Get the number of elements in an array
 */
#define countof(array) (sizeof(array)/sizeof(array[0]))

/**
 * Helper function that compares two strings for equality
 */
static inline bool streq(STR *x, STR *y)
{
        return strcmp(x, y) == 0;
}

/**
 * Macro compares two binary blobs for equality
 */
#define memeq(x,y,len) (memcmp(x, y, len) == 0)

/**
 * Call destructor of an object, if object != NULL
 */
#define DESTROY_IF(obj) if (obj) (obj)->destroy(obj)
/**
 * Macro gives back smaller of two values.
 */
#define min(x,y) ({ \
        typeof(x) _x = (x); \
        typeof(y) _y = (y); \
        _x < _y ? _x : _y; })


#define TIME_32_BIT_SIGNED_MAX  0x7fffffff
#define BUF_LEN 512
