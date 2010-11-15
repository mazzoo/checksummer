#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "checksummer.h"

#define INDICES_PER_LETTER 1024 * 10

indexer_t indexer[256];


void init_indexer(void)
{
	int i;
	for (i=0; i<256; i++)
	{
		indexer[i].offset = malloc(
			INDICES_PER_LETTER * sizeof(addr_t));
		memset(indexer[i].offset,
			0,
			INDICES_PER_LETTER * sizeof(addr_t));
		indexer[i].size = INDICES_PER_LETTER;
		indexer[i].next_free = 0;
	}
}

void create_index(image_t * img)
{
	addr_t a;
	for (a=0; a < img->size; a++)
	{
		indexer_t * letter = &indexer[img->map[a]];
		if (letter->next_free == letter->size)
		{
			LOG(LOG_INDEX, "  realloc for letter 0x%2.2x\n", img->map[a]);
			letter->offset = realloc(
				letter->offset,
				(letter->size + INDICES_PER_LETTER) * sizeof(addr_t)
			);
			letter->size += INDICES_PER_LETTER;
		}
		letter->offset[letter->next_free] = a;
		letter->next_free++;
	}

	LOG(LOG_INDEX, " letter distribution table [0x00 - 0xff]:\n\n");
	int i;
	for (i=0; i<256; i++)
	{
		LOG(LOG_INDEX, "%7d ", indexer[i].next_free);
		if((i%8)==7)
			LOG(LOG_INDEX, "\n");
	}
	LOG(LOG_INDEX, "\n");
	img->indexer = indexer;
}
