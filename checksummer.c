#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "checksummer.h"

#define ADDRESS_SPREAD        64
#define SEQ_THRESHOLD         64

#define MAX_ADDRESSES  1024*1024
#define NO_ADDRESS    0xffffffff

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

addr_t * address_list;

typedef void(*checksum_fp_t)
	(addr_t as, addr_t ae, image_t * img, uint8_t * byte_len, void ** result);

void sum32(addr_t as, addr_t ae, image_t * img, uint8_t * byte_len, void ** result)
{
	static uint32_t sum32 = 0;
	*byte_len = 4;

	uint32_t s32 = 0;

	static uint32_t cached_s32 = 0;
	static addr_t   cached_as = 0xffffffff;
	static addr_t   cached_ae = 0xffffffff;

	addr_t a;
	if ((as == cached_as) && (ae > cached_ae))
	{
		a   = cached_ae;
		s32 = cached_s32;
	}
	else
		a = as;

	for (; a<ae; a++)
		s32 += img->map[a];

	sum32 = s32;

	cached_s32 = s32;
	cached_as = as;
	cached_ae = ae;

	*result = &sum32;
}

void adler32(addr_t as, addr_t ae, image_t * img, uint8_t * byte_len, void ** result)
{
	static uint32_t a32 = 0;
	*byte_len = 4;

	uint32_t s1 = 1;
	uint32_t s2 = 0;

	static uint32_t cached_s1 = 1;
	static uint32_t cached_s2 = 0;
	static addr_t   cached_as = 0xffffffff;
	static addr_t   cached_ae = 0xffffffff;

	addr_t a;
	if ((as == cached_as) && (ae > cached_ae))
	{
		a  = cached_ae;
		s1 = cached_s1;
		s2 = cached_s2;
	}
	else
		a = as;

	for (; a<ae; a++)
	{
		s1 = (s1 + img->map[a]) % 65521;
		s2 = (s2 + s1) % 65521;
	}

	a32 = (s2 << 16) | s1;

	cached_s1 = s1;
	cached_s2 = s2;
	cached_as = as;
	cached_ae = ae;

	*result = &a32;
}


checksum_fp_t checksum_fps[] =
{
	sum32,
	adler32,
	NULL
};

char * checksum_name[] =
{
	"sum32",
	"adler32"
};

typedef struct checksum_cache_entry_s
{
	uint32_t sum;
	addr_t first_addr; /* = 0 if not found, first occurence otherwise */
	struct checksum_cache_entry_s * next;
} checksum_cache_entry_t;

checksum_cache_entry_t * checksum_cache4 = NULL;

void add_checksum_to_cache4(uint32_t c, addr_t found)
{
	checksum_cache_entry_t * p;
	checksum_cache_entry_t * ptmp;
	ptmp = checksum_cache4;

	p = malloc(sizeof(*p));
	checksum_cache4 = p;

	if (ptmp)
	{
		p->next = ptmp;
	}
	else
	{
		p->next = NULL;
	}

	p->sum = c;
	p->first_addr = found;
	//LOG(LOG_INFO, "new @%8.8x: %8.8x\n", found, c);
}

addr_t find_checksum_in_cache4(uint32_t c)
{
	checksum_cache_entry_t * p;
	p = checksum_cache4;
	while (p)
	{
		if (p->sum == c)
		{
			//LOG(LOG_INFO, "c4\n");
			return p->first_addr;
		}
		p = p->next;
	}
	return 0;
}

void find_checksum2(
                   image_t * img,
                   uint8_t clen,
                   void * result, 
                   uint32_t cindex,
                   addr_t as,
                   addr_t ae)
{
	int i;
	indexer_t letter = img->indexer[((uint8_t *)result)[0]];
	for (i=0; i < letter.next_free; i++)
	{
		uint8_t * p = &img->map[letter.offset[i]];
		if (unlikely(*(p+1) == ((uint8_t *)result)[1]))
		{
		if (unlikely(*(p+2) == ((uint8_t *)result)[2]))
		{
		if (unlikely(*(p+3) == ((uint8_t *)result)[3]))
		{
			LOG(LOG_INFO, "FOUND [0x%8.8x-0x%8.8x] checksum. %d bytes at 0x%8.8x: ", as, ae, clen, letter.offset[i]);
			int j;
			for (j=0; j<clen; j++)
				LOG(LOG_INFO, "%2.2x", img->map[letter.offset[i]+j]);
			LOG(LOG_INFO, " algorithm: %s\n", checksum_name[cindex]);
		}
		}
		}
	}
}

void find_checksum(
                   image_t * img,
                   uint8_t clen,
                   void * result, 
                   uint32_t cindex,
                   addr_t as,
                   addr_t ae)
{

	addr_t a = 0;

#ifdef CACHING
	int add_to_cache = 0;

	addr_t found = 0;

	if (clen == 4 && (*(uint32_t *) result))
		a = find_checksum_in_cache4(*(uint32_t *) result);

	if (!a)
		add_to_cache = 1;
	else
		return;
#endif

	uint8_t * p = &img->map[a];
	for (; a < img->size; a++)
	{

#if 0
		asm (
			"\tnop \n"
			"\tnop \n"
			"\tnop \n"
			"\tnop \n"
		);
#endif

		/* FIXME: this if..if..if..if construct reduces search time from
		 *        160s (memcmp) to 10s
		 *        the obvious downside: it's static for 32bit CRCs
		 *        replace with some while() construct
		 */
		if (unlikely(*(p+0) == ((uint8_t *)result)[0]))
		{
		if (unlikely(*(p+1) == ((uint8_t *)result)[1]))
		{
		if (unlikely(*(p+2) == ((uint8_t *)result)[2]))
		{
		if (unlikely(*(p+3) == ((uint8_t *)result)[3]))
		{
#ifdef CACHING
			if (!found)
				found = a;
#endif
			LOG(LOG_INFO, "FOUND [0x%8.8x-0x%8.8x] checksum. %d bytes at 0x%8.8x: ", as, ae, clen, a);
			int i;
			for (i=0; i<clen; i++)
				LOG(LOG_INFO, "%2.2x", img->map[a+i]);
			LOG(LOG_INFO, " algorithm: %s\n", checksum_name[cindex]);
#ifdef EXIT_AFTER_1ST_CHECKSUM_FOUND
			/* for performance measurements */
			exit(0);
#endif
		}
		}
		}
		}
		p++;
	}

#ifdef CACHING
	if (add_to_cache && clen == 4)
		add_checksum_to_cache4(*(uint32_t *) result, found);
#endif
}

void do_checksum(addr_t as, addr_t ae, image_t * img)
{
	checksum_fp_t * fp;
	fp = checksum_fps;
	uint8_t clen;
	void * result;
	uint32_t cindex = 0;
	while (*fp)
	{
		(*fp)(as, ae, img, &clen, &result);
//		find_checksum(img, clen, result, cindex, as, ae);
		find_checksum2(img, clen, result, cindex, as, ae);
		fp++;
		cindex++;
	}
}

void map_file(image_t * img)
{
	int ret;
	int f;
	f = open(img->fname, O_RDONLY);
	ret = lseek(f, 0, SEEK_END);
	img->size = ret;
	LOG(LOG_INFO, "mapping file %s size = %d/0x%x\n",
		img->fname, img->size, img->size);
	img->map = mmap(NULL, ret, PROT_READ, MAP_SHARED, f, 0);
}

void add_address(addr_t ** al, addr_t a)
{
	addr_t * p = *al;
	while (*p != NO_ADDRESS)
	{
		if (*p == a)
			return;
		p++;
	}
	*p = a;
	LOG(LOG_ADDR, "new address %8.8x\n", a);
}

void spread_addresses(addr_t ** al, uint32_t width)
{
	addr_t * p = *al;
	int n_addr = 0;
	while (*p != NO_ADDRESS)
	{
		n_addr++;
		p++;
	}
	int addr_count = n_addr;
	int i, j;
	p = *al;
	for (i=0; i<n_addr; i++, p++)
		for (j=1; j<width; j++)
		{
			add_address(al, *p + j);
			addr_count++;
			if (*p >= j )
			{
				add_address(al, *p - j);
				addr_count++;
			}
		}

	LOG(LOG_INFO, "spread to a total of %d addresses\n", addr_count);
}

void scan_img_for_addresses(image_t * img, addr_t ** al)
{
	uint8_t * p;
	addr_t a;
	int do_dump;
	addr_t sequence;
	uint32_t addr_count = 0;

	/* scanning for 0xFF->0xXX transitions */
	p        = img->map;
	do_dump  = 0;
	sequence = 0;
	for (a=0; a < img->size; a++)
	{
		if (*p == 0xff)
			sequence++;
		else
		{
			if (do_dump == 1)
			{
				LOG(LOG_SCAN, "interesting address 0x%8.8x after %6d 0xff\n", a, sequence);
				add_address(al, a);
				addr_count++;
				do_dump = 0;
			}
			sequence = 0;
		}
		if (sequence > SEQ_THRESHOLD)
			do_dump = 1;
		p++;
	}

	/* scanning for 0x00->0xXX transitions */
	p        = img->map;
	do_dump  = 0;
	sequence = 0;
	for (a=0; a < img->size; a++)
	{
		if (*p == 0x00)
			sequence++;
		else
		{
			if (do_dump == 1)
			{
				LOG(LOG_SCAN, "interesting address 0x%8.8x after %6d 0x00\n", a, sequence);
				add_address(al, a);
				addr_count++;
				do_dump = 0;
			}
			sequence = 0;
		}
		if (sequence > SEQ_THRESHOLD)
			do_dump = 1;
		p++;
	}
	LOG(LOG_INFO, "using %u interesting addresses\n", addr_count);
}

int main(int argc, char ** argv){
	image_t img;
	img.fname = malloc(strlen(argv[1])+1);
	memcpy(img.fname, argv[1], strlen(argv[1])+1);
	map_file(&img);
	address_list = malloc(MAX_ADDRESSES * sizeof(*address_list));
	memset(address_list, NO_ADDRESS, MAX_ADDRESSES * sizeof(*address_list));

	init_indexer();

	add_address(&address_list, 0);
	scan_img_for_addresses(&img, &address_list);

	spread_addresses(&address_list, ADDRESS_SPREAD);

	LOG(LOG_INDEX, "creating index ...\n");fflush(stdout);
	create_index(&img);
	LOG(LOG_INDEX, "creating index done.\n");fflush(stdout);

	int as; /* start address */
	int ae; /*   end address */
	/* O(n^2) */
	for (as=0; address_list[as] != NO_ADDRESS; as++)
	{
		for (ae=0; address_list[ae] != NO_ADDRESS; ae++)
		{
			/* FIXME we could use another parameter than ADDRESS_SPREAD */
			if (address_list[ae] > address_list[as] + ADDRESS_SPREAD)
			{
				LOG(LOG_ADDR,
				    "checksumming 0x%8.8x to 0x%8.8x\n",
				    address_list[as],
				    address_list[ae]);
				do_checksum(address_list[as], address_list[ae], &img);
			}
		}
	}

	return 0;
}
