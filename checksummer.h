#ifndef CHECKSUMMER_H
#define CHECKSUMMER_H

#include <stdint.h>

#define LOG_INFO      0x01
#define LOG_ERROR     0x02
#define LOG_ADDR      0x04
#define LOG_SCAN      0x08
#define LOG_INDEX     0x10

#define LOG_MASK   (\
                     LOG_INFO      |    \
                     LOG_ERROR     |    \
                  /* LOG_ADDR      | */ \
                     LOG_SCAN      |    \
                     LOG_INDEX     |    \
                     0\
                   )
#define LOG(level, fmt, args...)\
            {\
              if (level & LOG_MASK)\
              {\
                printf(fmt, ##args);\
                fflush(stdout);\
              }\
            }

typedef uint32_t addr_t;

typedef struct indexer_s {
	addr_t * offset;
	int      next_free;
	uint32_t size; /* of offset[] dynamically realloc()d */
} indexer_t;

typedef struct image_s{
	char    * fname;
	uint8_t * map;
	addr_t    size;
	indexer_t * indexer;
} image_t;

void init_indexer(void);
void create_index(image_t * img);

#endif /* CHECKSUMMER_H */
