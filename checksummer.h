#ifndef CHECKSUMMER_H
#define CHECKSUMMER_H

#include <stdint.h>

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
