// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2024 Nikita Travkin <nikita@trvn.ru> */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/disklabel.h>

#include <machine/armreg.h>

#include <lib/libkern/libkern.h>
#include <stand/boot/cmd.h>

#include <efi.h>
#include <efiapi.h>

#include "libsa.h"
#include "disk.h"

#include "sl.h"

extern EFI_BOOT_SERVICES	*BS;
extern EFI_MEMORY_DESCRIPTOR	*mmap;
extern UINTN			 mmap_ndesc;
extern UINTN			 mmap_descsiz;

extern void cpu_flush_dcache(vaddr_t addr, vsize_t len);

extern void tb_entry(void);
extern int tb_setjmp(uint64_t *jmp_buf) __attribute__((returns_twice));
extern int tb_longjmp(uint64_t *jmp_buf, uint64_t retval) __attribute__((noreturn));

extern uint64_t tb_jmp_buf[21];

static struct sl_smc_params *smc_data;
static uint64_t pe_data, pe_size, arg_data, arg_size;

int
slbounce(void)
{
	uint64_t smcret;

	smcret = sl_smc(smc_data, SL_CMD_AUTH, pe_data, pe_size, arg_data, arg_size);
	if (smcret) {
		printf("Failed to authenticate\n");
		return 1;
	}

	/* We set a special longjmp point here in hopes SL gets us back. */
	if (tb_setjmp(tb_jmp_buf) == 0) {
		cpu_flush_dcache((uint64_t)tb_jmp_buf, 8*21);
		smcret = sl_smc(smc_data, SL_CMD_LAUNCH, pe_data, pe_size, arg_data, arg_size);
		if (smcret) {
			printf("Failed to launch\n");
			return 1;
		}
	}

	return 0;
}

int
sl_install(void *tcb_data, size_t tcb_size)
{
	EFI_STATUS ret;
	uint64_t smcret = 0;

	ret = sl_create_data(tcb_data, tcb_size, &smc_data, &pe_data, &pe_size, &arg_data, &arg_size);
	if (ret != EFI_SUCCESS) {
		printf("Failed to prepare data for Secure-Launch: %llx\n", ret);
		return 1;
	}

	printf("Data creation is done. Trying to prepare Secure-Launch...\n");

	printf(" == Available: ");
	smcret = sl_smc(smc_data, SL_CMD_IS_AVAILABLE, pe_data, pe_size, arg_data, arg_size);
	printf("0x%llx\n", smcret);
	if (smcret) {
		printf("This device does not support Secure-Launch.\n");
		return 1;
	}

	return 0;
}

int
sl_init(void)
{
	EFI_PHYSICAL_ADDRESS addr;
	EFI_STATUS status;
	char path[MAXPATHLEN];
	struct stat sb;
	int fd;

	printf("SL-Bounce\n");
	printf("Running in EL=%llu\n", (READ_SPECIALREG(CurrentEL) >> 2) & 0x3);

	if (((READ_SPECIALREG(CurrentEL) >> 2) & 0x3) != 1) {
		printf("Already in EL2!\n\n");
		return 1;
	}

	snprintf(path, sizeof(path), "%s:%s", cmd.bootdev, "tcblaunch.exe");

	fd = open(path, O_RDONLY);
	if (fd < 0 || fstat(fd, &sb) == -1) {
		printf("cannot open %s\n", path);
		return 1;
	}
	status = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    EFI_SIZE_TO_PAGES(sb.st_size), &addr);
	if (status != EFI_SUCCESS) {
		printf("BS->AllocatePages()\n");
		return 1;
	}
	if (read(fd, (void *)addr, sb.st_size) != sb.st_size) {
		printf("cannot read from %s\n", path);
		return 1;
	}

	if (sl_install((void *)addr, sb.st_size) != 0) {
		printf("Installing SL hook failed\n");
		return 1;
	}

	return 0;
}
