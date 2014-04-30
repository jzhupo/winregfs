/* Threaded mode suffers from decreased performance */
#define ENABLE_THREADED 0

#define ENABLE_LOGGING 0
#define ENABLE_DEBUG_LOGGING 0
#define ENABLE_DEBUG_PRINTF 0

#define ENABLE_NKOFS_CACHE 1
#define ENABLE_NKOFS_CACHE_STATS 0
#define CACHE_ITEMS 64

/* Hash width. Set to 0 for uint_fast32_t */
/* Valid sizes: 8, 16, 32, 64 */
#define HASH 32
