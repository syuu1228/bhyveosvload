#ifndef _ELFPARSE_H_
#define _ELFPARSE_H_
#include <gelf.h>
#include <inttypes.h>
#include <sys/queue.h>

/* Internal data structure for sections. */
struct section {
	const char	*name;		/* section name */
	Elf_Scn		*scn;		/* section scn */
	uint64_t	 off;		/* section offset */
	uint64_t	 sz;		/* section size */
	uint64_t	 entsize;	/* section entsize */
	uint64_t	 align;		/* section alignment */
	uint64_t	 type;		/* section type */
	uint64_t	 flags;		/* section flags */
	uint64_t	 addr;		/* section virtual addr */
	uint32_t	 link;		/* section link ndx */
	uint32_t	 info;		/* section info ndx */
};

struct spec_name {
	const char	*name;
	STAILQ_ENTRY(spec_name)	sn_list;
};


/* Structure encapsulates the global data for readelf(1). */
struct elfparse {
	Elf		*elf;		/* underlying ELF descriptor. */
	GElf_Ehdr	 ehdr;		/* ELF header. */
	int		 ec;		/* ELF class. */
	size_t		 shnum;		/* #sections. */
	struct section	*sl;		/* list of sections. */
	STAILQ_HEAD(, spec_name) snl;	/* list of names specified by -N. */
};

int elfparse_open(int fd, struct elfparse *ep);
int elfparse_open_memory(char *image, size_t size, struct elfparse *ep);
int elfparse_close(struct elfparse *ep);
uintmax_t elfparse_resolve_symbol(struct elfparse *ep, char *name);

#endif
