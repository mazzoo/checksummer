#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define ADDRESS_SPREAD        64
#define SEQ_THRESHOLD         64

#define MAX_ADDRESSES  1024*1024
#define NO_ADDRESS    0xffffffff

#define LOG_INFO      0x01
#define LOG_ERROR     0x02
#define LOG_ADDR      0x04
#define LOG_SCAN      0x08

#define LOG_MASK   (\
                     LOG_INFO      |    \
                     LOG_ERROR     |    \
                     LOG_ADDR      |    \
                  /* LOG_ADDR      | */ \
                     LOG_SCAN      |    \
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

addr_t * address_list;

typedef struct image_s{
	char * fname;
	void * map;
	addr_t size;
} image_t;

void map_file(image_t * img)
{
	int ret;
	int f;
	f = open(img->fname, O_RDONLY);
	ret = lseek(f, 0, SEEK_END);
	img->size = ret;
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
	int i, j;
	p = *al;
	for (i=0; i<n_addr; i++, p++)
		for (j=1; j<width; j++)
			add_address(al, *p + j);
}

void scan_img_for_addresses(image_t * img, addr_t ** al)
{
	uint8_t * p;
	addr_t a;
	int do_dump;
	addr_t sequence;

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
				LOG(LOG_SCAN, "found address 0x%8.8x after %5.d 0xff\n", a, sequence);
				add_address(al, a);
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
				LOG(LOG_SCAN, "found address 0x%8.8x after %5.d 0x00\n", a, sequence);
				add_address(al, a);
				do_dump = 0;
			}
			sequence = 0;
		}
		if (sequence > SEQ_THRESHOLD)
			do_dump = 1;
		p++;
	}
}

int main(int argc, char ** argv){
	image_t img;
	img.fname = malloc(strlen(argv[1])+1);
	memcpy(img.fname, argv[1], strlen(argv[1])+1);
	map_file(&img);
	address_list = malloc(MAX_ADDRESSES * sizeof(*address_list));
	memset(address_list, NO_ADDRESS, MAX_ADDRESSES * sizeof(*address_list));

	add_address(&address_list, 0);
	scan_img_for_addresses(&img, &address_list);

	spread_addresses(&address_list, ADDRESS_SPREAD);

	int as; /* start address */
	int ae; /*   end address */
	for (as=0; as<MAX_ADDRESSES; as++)
	{
		if (address_list[as] == NO_ADDRESS)
			break;

		for (ae=0; ae<MAX_ADDRESSES; ae++)
		{
			if (address_list[ae] == NO_ADDRESS)
				break;

			if (address_list[ae] > address_list[as])
			{
				LOG(LOG_ADDR,
				    "checksumming 0x%8.8x to 0x%8.8x\n",
				    address_list[as],
				    address_list[ae]);
			}
		}
	}

	return 0;
}
