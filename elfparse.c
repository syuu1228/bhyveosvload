/*-
 * Copyright (c) 2007-2009 Kai Wang
 * Copyright (c) 2003 David O'Brien.  All rights reserved.
 * Copyright (c) 2001 Jake Burkholder
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <err.h>
#include "elfparse.h"


/*
 * Lookup a name in the '-N' name list.
 */
static struct spec_name *
find_name(struct elfparse *ed, const char *name)
{
	struct spec_name *sn;

	STAILQ_FOREACH(sn, &ed->snl, sn_list) {
		if (!strcmp(sn->name, name))
			return (sn);
	}

	return (NULL);
}


/*
 * Retrieve a string using string table section index and the string offset.
 */
static const char*
get_string(struct elfparse *ed, int strtab, size_t off)
{
	const char *name;

	if ((name = elf_strptr(ed->elf, strtab, off)) == NULL)
		return ("");

	return (name);
}

/*
 * Read the section headers from ELF object and store them in the
 * internal cache.
 */
static void
load_sections(struct elfparse *ed)
{
	struct section	*s;
	const char	*name;
	Elf_Scn		*scn;
	GElf_Shdr	 sh;
	size_t		 shstrndx, ndx;
	int		 elferr;

	assert(ed->sl == NULL);

	if (!elf_getshnum(ed->elf, &ed->shnum)) {
		warnx("elf_getshnum failed: %s", elf_errmsg(-1));
		return;
	}
	if (ed->shnum == 0)
		return;
	if ((ed->sl = calloc(ed->shnum, sizeof(*ed->sl))) == NULL)
		err(EXIT_FAILURE, "calloc failed");
	if (!elf_getshstrndx(ed->elf, &shstrndx)) {
		warnx("elf_getshstrndx failed: %s", elf_errmsg(-1));
		return;
	}
	if ((scn = elf_getscn(ed->elf, 0)) == NULL) {
		warnx("elf_getscn failed: %s", elf_errmsg(-1));
		return;
	}
	(void) elf_errno();
	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("gelf_getshdr failed: %s", elf_errmsg(-1));
			(void) elf_errno();
			continue;
		}
		if ((name = elf_strptr(ed->elf, shstrndx, sh.sh_name)) == NULL) {
			(void) elf_errno();
			name = "ERROR";
		}
		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF)
			if ((elferr = elf_errno()) != 0) {
				warnx("elf_ndxscn failed: %s",
				    elf_errmsg(elferr));
				continue;
			}
		if (ndx >= ed->shnum) {
			warnx("section index of '%s' out of range", name);
			continue;
		}
		s = &ed->sl[ndx];
		s->name = name;
		s->scn = scn;
		s->off = sh.sh_offset;
		s->sz = sh.sh_size;
		s->entsize = sh.sh_entsize;
		s->align = sh.sh_addralign;
		s->type = sh.sh_type;
		s->flags = sh.sh_flags;
		s->addr = sh.sh_addr;
		s->link = sh.sh_link;
		s->info = sh.sh_info;
	} while ((scn = elf_nextscn(ed->elf, scn)) != NULL);
	elferr = elf_errno();
	if (elferr != 0)
		warnx("elf_nextscn failed: %s", elf_errmsg(elferr));
}

/*
 * Release section related resources.
 */
static void
unload_sections(struct elfparse *ed)
{
	if (ed->sl != NULL) {
		free(ed->sl);
		ed->sl = NULL;
	}
}

static void
elf_find_symbol_symtab(struct elfparse *ed, int i, char *name, GElf_Sym *sym)
{
	struct section	*s;
	const char	*sname;
	uint16_t	*vs;
	Elf_Data	*data;
	int		 len, j, elferr, nvs;

	s = &ed->sl[i];
	(void) elf_errno();
	if ((data = elf_getdata(s->scn, NULL)) == NULL) {
		elferr = elf_errno();
		if (elferr != 0)
			fprintf(stderr, "elf_getdata failed: %s", elf_errmsg(elferr));
		return;
	}
	vs = NULL;
	nvs = 0;
	len = data->d_size / s->entsize;
	for (j = 0; j < len; j++) {
		if (gelf_getsym(data, j, sym) != sym) {
			fprintf(stderr, "gelf_getsym failed: %s", elf_errmsg(-1));
			continue;
		}
		sname = get_string(ed, s->link, sym->st_name);
		if (!strcmp(sname, name))
			return;
	}
}


static void
elf_find_symbol(struct elfparse *ed, char *name, GElf_Sym *sym)
{
	int i;

	for (i = 0; (size_t)i < ed->shnum; i++)
		if ((ed->sl[i].type == SHT_SYMTAB ||
		    ed->sl[i].type == SHT_DYNSYM) &&
		    (STAILQ_EMPTY(&ed->snl) || find_name(ed, ed->sl[i].name)))
			elf_find_symbol_symtab(ed, i, name, sym);
}


uintmax_t
elfparse_resolve_symbol(struct elfparse *ed, char *name)
{
	GElf_Sym sym;

	load_sections(ed);
	elf_find_symbol(ed, name, &sym);
	unload_sections(ed);

	return sym.st_value;
}

int 
elfparse_open(int fd, struct elfparse *ed)
{
	memset(ed, 0, sizeof(*ed));
	STAILQ_INIT(&ed->snl);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "ELF library initialization failed: %s",
		    elf_errmsg(-1));
		return -1;
	}
	if ((ed->elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		warnx("elf_begin() failed: %s", elf_errmsg(-1));
		return -1;
	}
	if (elf_kind(ed->elf) != ELF_K_ELF) {
		fprintf(stderr, "invalid format\n");
		return -1;
	}
	if (gelf_getehdr(ed->elf, &ed->ehdr) == NULL) {
		warnx("gelf_getehdr failed: %s", elf_errmsg(-1));
		return -1;
	}
	if ((ed->ec = gelf_getclass(ed->elf)) == ELFCLASSNONE) {
		warnx("gelf_getclass failed: %s", elf_errmsg(-1));
		return -1;
	}

	return 0;
}

int 
elfparse_open_memory(char *image, size_t size, struct elfparse *ed)
{
	memset(ed, 0, sizeof(*ed));
	STAILQ_INIT(&ed->snl);
	if (elf_version(EV_CURRENT) == EV_NONE) {
		errx(EXIT_FAILURE, "ELF library initialization failed: %s",
		    elf_errmsg(-1));
		return -1;
	}
	if ((ed->elf = elf_memory(image, size)) == NULL) {
		warnx("elf_begin() failed: %s", elf_errmsg(-1));
		return -1;
	}
	if (elf_kind(ed->elf) != ELF_K_ELF) {
		fprintf(stderr, "invalid format\n");
		return -1;
	}
	if (gelf_getehdr(ed->elf, &ed->ehdr) == NULL) {
		warnx("gelf_getehdr failed: %s", elf_errmsg(-1));
		return -1;
	}
	if ((ed->ec = gelf_getclass(ed->elf)) == ELFCLASSNONE) {
		warnx("gelf_getclass failed: %s", elf_errmsg(-1));
		return -1;
	}

	return 0;
}

int 
elfparse_close(struct elfparse *ed)
{
	elf_end(ed->elf);
	return 0;
}
