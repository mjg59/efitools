typedef unsigned char bool;
typedef unsigned char u_char;
typedef unsigned int u_int;

static const bool FALSE = 0;
static const bool TRUE = 1;

#define DEBUG(a...)
#define DBG1(...)
#define DBG2(...)

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
static inline bool streq(const char *x, const char *y)
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
