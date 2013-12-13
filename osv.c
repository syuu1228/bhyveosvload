/*-
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: user/syuu/bhyve_standalone_guest/usr.sbin/bhyveload/bhyveload.c 253922 2013-08-04 01:22:26Z syuu $
 */

/*-
 * Copyright (c) 2011 Google, Inc.
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
 *
 * $FreeBSD: user/syuu/bhyve_standalone_guest/usr.sbin/bhyveload/bhyveload.c 253922 2013-08-04 01:22:26Z syuu $
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: user/syuu/bhyve_standalone_guest/usr.sbin/bhyveload/bhyveload.c 253922 2013-08-04 01:22:26Z syuu $");

#include <sys/stat.h>
#include <sys/param.h>

#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <x86/segments.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vmmapi.h>

#include "elfparse.h"
#include "userboot.h"

#define	BSP	0
#define	DESC_UNUSABLE		0x00010000

#define ADDR_CMDLINE 0x7e00
#define ADDR_TARGET 0x200000
#define ADDR_MB_INFO 0x1000
#define ADDR_E820DATA 0x1100
#define ADDR_STACK 0x1200
#define ADDR_PT4 0x2000
#define ADDR_PT3 0x3000
#define ADDR_PT2 0x4000
#define ADDR_GDTR 0x5000

struct multiboot_info_type {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
    uint32_t drives_length;
    uint32_t drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
    uint32_t apm_table;
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
} __attribute__((packed));

struct e820ent {
    uint32_t ent_size;
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define MSR_EFER        0xc0000080
#define CR4_PAE         0x00000020
#define CR4_PSE         0x00000010
#define CR0_PG          0x80000000
#define	CR0_PE		0x00000001	/* Protected mode Enable */
#define	CR0_NE		0x00000020	/* Numeric Error enable (EX16 vs IRQ13) */

#define PG_V	0x001
#define PG_RW	0x002
#define PG_U	0x004
#define PG_PS	0x080

typedef u_int64_t p4_entry_t;
typedef u_int64_t p3_entry_t;
typedef u_int64_t p2_entry_t;

#define	GUEST_GDTR_LIMIT	(4 * 8 - 1)

int osv_load(struct loader_callbacks *cb, uint64_t mem_size);

static void
setup_osv_gdt(uint64_t *gdtr)
{
	gdtr[0] = 0x0;
	gdtr[1] = 0x00af9b000000ffff; 
	gdtr[2] = 0x00cf93000000ffff;
	gdtr[3] = 0x00cf9b000000ffff;
}

extern struct vmctx *ctx;
extern int disk_fd;

int
osv_load(struct loader_callbacks *cb, uint64_t mem_size)
{
#if 0
	int i;
#endif
	struct multiboot_info_type mb_info;
	struct e820ent e820data[3];
	char cmdline[0x3f * 512];
	void *target;
	size_t resid;
	struct elfparse ep;
	uint64_t start64, ident_pt_l4, gdt_desc;
	int error;
	uint64_t desc_base;
	uint32_t desc_access, desc_limit;
	uint16_t gsel;
	ssize_t siz;
#if 0
	p4_entry_t PT4[512];
	p3_entry_t PT3[512];
	p2_entry_t PT2[512];
	uint64_t gdtr[3];
#endif

	bzero(&mb_info, sizeof(mb_info));
	mb_info.cmdline = ADDR_CMDLINE;
	mb_info.mmap_addr = ADDR_E820DATA;
	mb_info.mmap_length = sizeof(e820data);
	printf("sizeof e820data=%lx\n", sizeof(e820data));
	if (cb->copyin(NULL, &mb_info, ADDR_MB_INFO, sizeof(mb_info))) {
		perror("copyin");
		return (1);
	}
	cb->setreg(NULL, VM_REG_GUEST_RBX, ADDR_MB_INFO);

	e820data[0].ent_size = 20;
	e820data[0].addr = 0x0;
	e820data[0].size = 654336;
	e820data[0].type = 1;
	e820data[1].ent_size = 20;
	e820data[1].addr = 0x100000;
	e820data[1].size = mem_size - 0x100000;
	e820data[1].type = 1;
	e820data[2].ent_size = 20;
	e820data[2].addr = 0;
	e820data[2].size = 0;
	e820data[2].type = 0;
	if (cb->copyin(NULL, e820data, ADDR_E820DATA, sizeof(e820data))) {
		perror("copyin");
		return (1);
	}

	if (cb->diskread(NULL, 0, 1 * 512, cmdline, 63 * 512, &resid)) {
		perror("diskread");
	}
	printf("cmdline=%s\n", cmdline);
	if (cb->copyin(NULL, cmdline, ADDR_CMDLINE, sizeof(cmdline))) {
		perror("copyin");
		return (1);
	}

	target = calloc(1, 0x40 * 512 * 4096);
	if (!target) {
		perror("calloc");
		return (1);
	}
#if 0 /* XXX: Why this doesn't work? */
	if (cb->diskread(NULL, 0, 0x40 * 512 * 4096, target, 128 * 512, &resid)) {
		perror("diskread");
		return (1);
	}
#endif
	siz = pread(disk_fd, target, 0x40 * 512 * 4096, 128 * 512);
	if (siz < 0)
		perror("pread");
	if (cb->copyin(NULL, target, ADDR_TARGET, 0x40 * 512 * 4096)) {
		perror("copyin");
		return (1);
	}
	if (elfparse_open_memory(target, 0x40 * 512 * 4096, &ep)) {
		return (1);
	}
	start64 = elfparse_resolve_symbol(&ep, "start64");
	ident_pt_l4 = elfparse_resolve_symbol(&ep, "ident_pt_l4");
	gdt_desc = elfparse_resolve_symbol(&ep, "gdt_desc");
	printf("start64:0x%lx\n", start64);
	printf("ident_pt_l4:0x%lx\n", ident_pt_l4);
	printf("gdt_desc:0x%lx\n", gdt_desc);

	desc_base = 0;
	desc_limit = 0;
	desc_access = 0x0000209B;
	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_CS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	desc_access = 0x00000093;
	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_DS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_ES,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_FS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_GS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_SS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	/*
	 * XXX TR is pointing to null selector even though we set the
	 * TSS segment to be usable with a base address and limit of 0.
	 */
	desc_access = 0x0000008b;
	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_TR, 0, 0, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(ctx, BSP, VM_REG_GUEST_LDTR, 0, 0,
			    DESC_UNUSABLE);
	if (error)
		goto done;

	gsel = GSEL(1, SEL_KPL);
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_CS, gsel)) != 0)
		goto done;
	
	gsel = GSEL(2, SEL_KPL);
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_DS, gsel)) != 0)
		goto done;
	
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_ES, gsel)) != 0)
		goto done;

	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_FS, gsel)) != 0)
		goto done;
	
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_GS, gsel)) != 0)
		goto done;
	
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_SS, gsel)) != 0)
		goto done;

	/* XXX TR is pointing to the null selector */
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_TR, 0)) != 0)
		goto done;

	/* LDTR is pointing to the null selector */
	if ((error = vm_set_register(ctx, BSP, VM_REG_GUEST_LDTR, 0)) != 0)
		goto done;

#if 0
	bzero(PT4, PAGE_SIZE);
	bzero(PT3, PAGE_SIZE);
	bzero(PT2, PAGE_SIZE);

	/*
	 * This is kinda brutal, but every single 1GB VM memory segment
	 * points to the same first 1GB of physical memory.  But it is
	 * more than adequate.
	 */
	for (i = 0; i < 512; i++) {
		/* Each slot of the level 4 pages points to the same level 3 page */
		PT4[i] = (p4_entry_t) ADDR_PT3;
		PT4[i] |= PG_V | PG_RW | PG_U;

		/* Each slot of the level 3 pages points to the same level 2 page */
		PT3[i] = (p3_entry_t) ADDR_PT2;
		PT3[i] |= PG_V | PG_RW | PG_U;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		PT2[i] = i * (2 * 1024 * 1024);
		PT2[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}

	cb->copyin(NULL, PT4, ADDR_PT4, sizeof(PT4));
	cb->copyin(NULL, PT3, ADDR_PT3, sizeof(PT3));
	cb->copyin(NULL, PT2, ADDR_PT2, sizeof(PT2));
#endif

	cb->setreg(NULL, VM_REG_GUEST_RFLAGS, 0x2);
	cb->setreg(NULL, VM_REG_GUEST_RBP, ADDR_TARGET);
	cb->setreg(NULL, VM_REG_GUEST_RSP, ADDR_STACK);
	cb->setmsr(NULL, MSR_EFER, 0x00000d00);
	cb->setcr(NULL, 4, 0x000007b8);
#if 0
	cb->setcr(NULL, 3, ADDR_PT4);
#endif
	cb->setcr(NULL, 3, ident_pt_l4);
	cb->setcr(NULL, 0, 0x80010001);

#if 0
	setup_osv_gdt(gdtr);
	cb->copyin(NULL, gdtr, ADDR_GDTR, sizeof(gdtr));
        cb->setgdt(NULL, ADDR_GDTR, sizeof(gdtr));
#endif
        cb->setgdt(NULL, gdt_desc, sizeof(uint64_t) * 4);
	cb->setreg(NULL, VM_REG_GUEST_RIP, start64);
	return (0);
done:
	return (error);
}

