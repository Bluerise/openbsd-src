// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2024 Nikita Travkin <nikita@trvn.ru> */

#define EFI_DEBUG 1

#include <sys/param.h>
#include <machine/armreg.h>

#include <efi.h>
#include <efiapi.h>

#include <lib/libkern/libkern.h>

#include "libsa.h"
#include "sl.h"
#include "winnt.h"

extern EFI_BOOT_SERVICES	*BS;

extern void cpu_flush_dcache(vaddr_t addr, vsize_t len);
extern void tb_entry(void);
extern uint64_t tb_jmp_buf[21];

static void
smc_exec(uint64_t *in, uint64_t *out)
{
	__asm(
	    "ldp x0, x1, [%0, #0]\n"
	    "ldp x2, x3, [%0, #16]\n"
	    "ldp x4, x5, [%0, #32]\n"
	    "ldp x6, x7, [%0, #48]\n"
	    "smc #0\n"
	    "stp x0, x1, [%1, #0]\n"
	    "stp x2, x3, [%1, #16]\n"
	    "stp x4, x5, [%1, #32]\n"
	    "stp x6, x7, [%1, #48]\n" ::
	    "r" (in), "r" (out) :
	    "x0", "x1", "x2", "x3",
	    "x4", "x5", "x6", "x7",
	    "memory");
}

static uint64_t
smc(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3)
{
	uint32_t daif = READ_SPECIALREG(daif);
	__asm volatile("msr daifset, #3");

	uint64_t in[8] = { x0, x1, x2, x3, 0, 0, 0, 0 }, out[6] = { 0 };
	smc_exec(in, out);

	WRITE_SPECIALREG(daif, daif);
	return out[0];
}

/**
 * sl_get_cert_entry() - Get a pointer to the start of the security structure in PE.
 */
EFI_STATUS sl_get_cert_entry(UINT8 *tcb_data, UINT8 **data, UINT64 *size)
{
	if (!tcb_data || !data || !size)
		return EFI_INVALID_PARAMETER;

	PIMAGE_DOS_HEADER pe = (PIMAGE_DOS_HEADER)tcb_data;

	if (pe->e_magic != IMAGE_DOS_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8 *)pe + pe->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	if (nt->OptionalHeader.Magic != 0x20b)
		return EFI_INVALID_PARAMETER;

	PIMAGE_DATA_DIRECTORY security = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

	printf("Security entry at offt 0x%x with size 0x%x\n", security->VirtualAddress, security->Size);

	*data = (UINT8 *)pe + security->VirtualAddress;
	*size = security->Size;

	PWIN_CERTIFICATE cert = (PWIN_CERTIFICATE)*data;

	printf("Cert: Len=0x%x, Rev=0x%x, Type=0x%x\n", cert->dwLength, cert->wRevision, cert->wCertificateType);

	if (cert->wRevision != 0x200 || cert->wCertificateType != 2)
		return EFI_INVALID_PARAMETER;

	return EFI_SUCCESS;
}

/**
 * sl_load_pe() - Load a PE image into memory.
 *
 * We want to make sure we just load the image header and the
 * sections into ram as-is since we expect them to be signature
 * checked later.
 */
EFI_STATUS sl_load_pe(UINT8 *load_addr, UINT64 load_size, UINT8 *pe_data, UINT64 pe_size)
{
	if (!load_addr || !load_size || !pe_data || !pe_size)
		return EFI_INVALID_PARAMETER;

	PIMAGE_DOS_HEADER pe = (PIMAGE_DOS_HEADER)pe_data;

	if (pe->e_magic != IMAGE_DOS_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8 *)pe + pe->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	if (nt->OptionalHeader.Magic != 0x20b)
		return EFI_INVALID_PARAMETER;

	if (nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
		return EFI_INVALID_PARAMETER;

	memset(load_addr, 0, load_size);

	printf("Loadint PE header with %d bytes to 0x%x\n", nt->OptionalHeader.SizeOfHeaders, load_addr);

	memcpy(load_addr, pe, nt->OptionalHeader.SizeOfHeaders); // Header

	PIMAGE_SECTION_HEADER headers = (PIMAGE_SECTION_HEADER)((UINT8*)nt + 0x108);
	UINT64 header_count = nt->FileHeader.NumberOfSections;

	// FIXME this should probably handle errors better...
	for (int i = 0; i < header_count; ++i) {
		printf(" - Loading section '%.*a' with %d bytes from offt=0x%x to 0x%x\n",
			8, headers[i].Name, headers[i].SizeOfRawData,
			headers[i].PointerToRawData,
			load_addr + headers[i].VirtualAddress);

		KASSERT(headers[i].VirtualAddress + headers[i].SizeOfRawData < load_size);

		memcpy(load_addr + headers[i].VirtualAddress,
			(UINT8*)pe + headers[i].PointerToRawData,
			headers[i].SizeOfRawData); // I hope rawdata size is correct, this is how much is hashed...
	}

	return EFI_SUCCESS;
}

uint64_t sl_smc(struct sl_smc_params *smc_data, enum sl_cmd cmd, uint64_t pe_data, uint64_t pe_size, uint64_t arg_data, uint64_t arg_size)
{
	/*
	 * Some versions of the hyp will clean the memory before
	 * unmapping it from EL2. We need to recreate the smc_data
	 * every time.
	 */
	smc_data->a = 1;
	smc_data->b = 0;
	smc_data->version = 0x10;
	smc_data->pe_data = pe_data;
	smc_data->pe_size = pe_size;
	smc_data->arg_data = arg_data;
	smc_data->arg_size = arg_size;

	smc_data->num = cmd;
	cpu_flush_dcache((uint64_t)smc_data, 4096 * 1);

	return smc(SMC_SL_ID, (uint64_t)smc_data, smc_data->num, 0);
}

EFI_STATUS sl_create_data(uint8_t *tcb_tmp_file, size_t tcb_size, struct sl_smc_params **smcdata, uint64_t *pe_data, uint64_t *pe_size, uint64_t *arg_data, uint64_t *arg_size)
{
	EFI_STATUS ret;

	/* Allocate and load the tcblaunch.exe file. */

	UINT64 tcb_pages = 512; // FIXME: don't hardcode...
	EFI_PHYSICAL_ADDRESS tcb_phys = 0;

	ret = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    tcb_pages, &tcb_phys);
	if (ret != EFI_SUCCESS) {
		printf("BS->AllocatePages()\n");
		goto exit;
	}
	bzero((void *)tcb_phys, tcb_pages * 4096);

	printf("Allocated %d pages at 0x%x (TCB)\n", tcb_pages, tcb_phys);

	UINT8 *tcb_data = (UINT8 *)tcb_phys;

	/* Load the PE into memory */
	ret = sl_load_pe(tcb_data, tcb_pages * 4096, tcb_tmp_file, tcb_size);
	if (ret != EFI_SUCCESS) {
		printf("PE format is invalid.\n");
		goto exit_tcb;
	}

	/* Extract the certificate/signature section address. */
	UINT8 *cert_data;
	UINT64 cert_size;

	ret = sl_get_cert_entry(tcb_tmp_file, &cert_data, &cert_size);
	if (ret != EFI_SUCCESS) {
		printf("Can't get cert pointers\n");
		goto exit_tcb;
	}

	UINT64 cert_pages = cert_size / 4096 + 1;

	/* Allocate a buffer for Secure Launch procecss. */

	EFI_PHYSICAL_ADDRESS buf_phys = 0;
	UINT64 buf_pages = 27 + cert_pages + 3;

	ret = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    buf_pages, &buf_phys);
	if (ret != EFI_SUCCESS) {
		printf("BS->AllocatePages()\n");
		goto exit_tcb;
	}
	bzero((void *)buf_phys, buf_pages * 4096);

	printf("Allocated %d pages at 0x%x (data, cert pages = %d)\n", buf_pages, buf_phys, cert_pages);

	/*
	 * Our memory map for pages in this buffer is:
	 *
	 * | Off| Usage			|
	 * |----|-----------------------|
	 * | 0	| (Unused)		|
	 * | 1	| SMC data		|
	 * | 2	| TZ data		|
	 * | 3	| TCB's CRT memory	|
	 * | 27	| Cert entry		|
	 * | ??	| TCG Log		|
	 *
	 */

	UINT8 *buf = (UINT8 *)buf_phys;

	struct sl_smc_params *smc_data = (struct sl_smc_params *)(buf + 4096 * 1);
	struct sl_tz_data    *tz_data  =    (struct sl_tz_data *)(buf + 4096 * 2);

	tz_data->version = 1;
	tz_data->cert_offt = 4096 * 25;
	tz_data->cert_size = cert_size;

	UINT8 *buf_cert_data = (UINT8*)tz_data + tz_data->cert_offt;
	memcpy(buf_cert_data, cert_data, cert_size);

	/* FIXME Don't need raw PE anymore. */

	tz_data->tcg_offt = tz_data->cert_offt + cert_size;
	tz_data->tcg_size = 4096 * 2;
	tz_data->tcg_used = 0;
	tz_data->tcg_ver = 2;

	tz_data->this_size = 4096 * (buf_pages - 3);
	tz_data->this_phys = (uint64_t)tz_data;

	tz_data->crt_offt = 4096 * 1;
	tz_data->crt_pages_cnt = 24;

	/* Set up return code path for when tcblaunch.exe fails to start */

	// FIXME: Probably better to just add an extra section into the PE.
	tz_data->tb_entry_point = (uint64_t)tb_entry;
	tz_data->tb_virt = (tz_data->tb_entry_point & 0xfffffffffffff000);
	tz_data->tb_phys = tz_data->tb_virt;
	tz_data->tb_size = 4096 * 2;
	tz_data->tb_data.mair = (uint64_t)tb_jmp_buf;

	printf("TB entrypoint is 0x%x, Image is at 0x%x, size= 0x%x, data[0]= 0x%x\n",
		tz_data->tb_entry_point, tz_data->tb_virt, tz_data->tb_size, tz_data->tb_data.mair);

	/* Allocate (bogus) boot parameters for tcb. */

	EFI_PHYSICAL_ADDRESS bootparams_phys = 0;
	UINT64 bootparams_pages = 3;

	ret = BS->AllocatePages(AllocateAnyPages, EfiLoaderData,
	    bootparams_pages, &bootparams_phys);
	if (ret != EFI_SUCCESS) {
		printf("BS->AllocatePages()\n");
		goto exit_buf;
	}
	bzero((void *)bootparams_phys, bootparams_pages * 4096);

	printf("Allocated %d pages at 0x%x (bootparams)\n", bootparams_pages, bootparams_phys);

	struct sl_boot_params *bootparams = (struct sl_boot_params *)bootparams_phys;
	/*
	 * We don't really care what's in bootparams as long as it's garbage.
	 * Setting it all to 0xFF would guarantee the sanity checks to fail
	 * in tcblaunch.exe and make it transition back into whoever started it.
	 */
	memset(bootparams, 0xff, 4096 * bootparams_pages);

	tz_data->boot_params = (uint64_t)bootparams;
	tz_data->boot_params_size = 4096 * bootparams_pages;

	*smcdata  = smc_data;
	*pe_data  = (uint64_t)tcb_data;
	*pe_size  = 4096 * tcb_pages;
	*arg_data = tz_data->this_phys;
	*arg_size = tz_data->this_size;

	/* Do some sanity checks */

	/* mssecapp.mbn */
	KASSERT(*arg_data != 0);
	KASSERT(*arg_size > 0x17);
	KASSERT(*pe_data != 0);
	KASSERT(*pe_size != 0);

#ifdef DIAGNOSTIC
	PIMAGE_DOS_HEADER pe = (PIMAGE_DOS_HEADER)*pe_data;
	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UINT8 *)pe + pe->e_lfanew);
#endif
	KASSERT(pe->e_magic == IMAGE_DOS_SIGNATURE);
	KASSERT(nt->Signature == IMAGE_NT_SIGNATURE);
	KASSERT(nt->OptionalHeader.Magic == 0x20b);

	KASSERT(tz_data->version == 1);
	KASSERT(tz_data->cert_offt > 0x17);
	KASSERT(tz_data->cert_size != 0);
	KASSERT(tz_data->this_size > tz_data->cert_offt);
	KASSERT(tz_data->this_size - tz_data->cert_offt >= tz_data->cert_size);
	KASSERT(tz_data->tcg_offt > 0x17);
	KASSERT(tz_data->tcg_size != 0);
	KASSERT(tz_data->this_size > tz_data->tcg_offt);
	KASSERT(tz_data->this_size - tz_data->tcg_offt >= tz_data->tcg_size);

	/* tcblaunch.exe */
	KASSERT(tz_data->tb_entry_point != 0);
	KASSERT(tz_data->tb_virt == tz_data->tb_phys);
	KASSERT(tz_data->tb_size > 0);

	/* Leftovers from winload.efi doing SL */
	KASSERT(sizeof(struct sl_tz_data) == 0xc8);
	KASSERT(tz_data->tcg_size == 0x2000);
	KASSERT(tz_data->tcg_used == 0x0);
	KASSERT(tz_data->tcg_ver == 0x2);
	KASSERT(tz_data->crt_offt == 0x1000);
	KASSERT(tz_data->crt_pages_cnt == 0x18);
	KASSERT(tz_data->boot_params_size == 0x3000);

	/* These depend on tcblaunch.exe from 22H2 */
	//ASSERT(tz_data->cert_offt == 0x19000);
	//ASSERT(tz_data->cert_size == 0x4030);
	//ASSERT(tz_data->tcg_offt == 0x01d030);
	//ASSERT(tz_data->this_size == 0x20000);

	cpu_flush_dcache((uint64_t)tcb_data, 4096 * tcb_pages);
	cpu_flush_dcache((uint64_t)buf, 4096 * buf_pages);
	cpu_flush_dcache((uint64_t)bootparams, 4096 * bootparams_pages);

	return EFI_SUCCESS;

	BS->FreePages(bootparams_phys, bootparams_pages);

exit_buf:
	BS->FreePages(buf_phys, buf_pages);

exit_tcb:
	BS->FreePages(tcb_phys, tcb_pages);

exit:
	return ret;
}
