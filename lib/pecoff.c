/*
 * Code Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Functions cut and pasted from
 *
 *   git://github.com/mjg59/shim.git
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ---
 *
 * This file is a functional simplification of Original code from TianoCore
 * (http://tianocore.sf.net)
 *
 *   MdePkg/Library/BasePeCoffLib/BasePeCoff.c
 *
 * Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
 * Portions copyright (c) 2008 - 2009, Apple Inc. All rights reserved.<BR>
 * This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found at
 * http://opensource.org/licenses/bsd-license.php.
 *
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 */

#include <efi.h>
#include <efilib.h>

#include <pecoff.h>
#include <guid.h>
#include <simple_file.h>
#include <variables.h>
#include <sha256.h>
#include <errors.h>

#ifndef BUILD_EFI
#define Print(...) do { } while(0)
#define AllocatePool(x) malloc(x)
#define CopyMem(d, s, l) memcpy(d, s, l)
#define ZeroMem(s, l) memset(s, 0, l)
#endif

EFI_STATUS
pecoff_read_header(PE_COFF_LOADER_IMAGE_CONTEXT *context, void *data)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;

	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE)
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);

	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		Print(L"Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		Print(L"Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	if (PEHdr->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Print(L"Only 64-bit images supported\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;
	context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
	context->ImageSize = (UINT64)PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
	context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
	context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
	context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
	context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;
	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)((char *)PEHdr + PEHdr->Pe32.FileHeader.SizeOfOptionalHeader + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER));
	context->SecDir = (EFI_IMAGE_DATA_DIRECTORY *) &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	if (context->SecDir->VirtualAddress >= context->ImageSize) {
		Print(L"Malformed security header\n");
		return EFI_INVALID_PARAMETER;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
pecoff_image_layout(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data)
{
	void *buffer = AllocatePool(context->ImageSize);
	EFI_IMAGE_SECTION_HEADER *s;
	int i, size;
	char *base, *end;

	CopyMem(buffer, *data, context->SizeOfHeaders);

	for (i = 0; i < context->NumberOfSections; i++) {
		s = &context->FirstSection[i];
		size = s->Misc.VirtualSize;
	
		if (size > s->SizeOfRawData)
			size = s->SizeOfRawData;
		base = pecoff_image_address(buffer, context->ImageSize, s->VirtualAddress);
		end = pecoff_image_address(buffer, context->ImageSize, s->VirtualAddress + size - 1);

		if (!base || !end) {
			Print(L"Invalid section size\n");
			return EFI_UNSUPPORTED;
		}

		if (s->SizeOfRawData > 0)
			CopyMem(base, *data + s->PointerToRawData, size);

		if (size < s->Misc.VirtualSize)
			ZeroMem (base + size, s->Misc.VirtualSize - size);

	}
	//FreePool(*data);
	*data = buffer;

	return EFI_SUCCESS;
}

EFI_STATUS
pecoff_relocate(PE_COFF_LOADER_IMAGE_CONTEXT *context, void **data)
{
	EFI_IMAGE_BASE_RELOCATION *RelocBase, *RelocBaseEnd;
	UINT64 Adjust;
	UINT16 *Reloc, *RelocEnd;
	char *Fixup, *FixupBase, *FixupData = NULL;
	UINT16 *Fixup16;
	UINT32 *Fixup32;
	UINT64 *Fixup64;
	int size = context->ImageSize;
	void *ImageEnd = (char *)data + size;
	EFI_STATUS efi_status;

	efi_status = pecoff_image_layout(context, data);
	if (efi_status != EFI_SUCCESS) {
		Print(L"pecoff_image_layout: failed to layout image\n");
		return efi_status;
	}

	context->PEHdr->Pe32Plus.OptionalHeader.ImageBase = (UINT64)*data;

	if (context->NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		Print(L"Image has no relocation entry\n");
		return EFI_UNSUPPORTED;
	}

	RelocBase = pecoff_image_address(*data, size, context->RelocDir->VirtualAddress);
	RelocBaseEnd = pecoff_image_address(*data, size, context->RelocDir->VirtualAddress + context->RelocDir->Size - 1);

	if (!RelocBase || !RelocBaseEnd) {
		Print(L"Reloc table overflows binary %d %d\n",
		      context->RelocDir->VirtualAddress,
		      context->RelocDir->VirtualAddress + context->RelocDir->Size - 1);
		return EFI_UNSUPPORTED;
	}

	Adjust = (UINT64)*data - context->ImageAddress;

	while (RelocBase < RelocBaseEnd) {
		Reloc = (UINT16 *) ((char *) RelocBase + sizeof (EFI_IMAGE_BASE_RELOCATION));
		RelocEnd = (UINT16 *) ((char *) RelocBase + RelocBase->SizeOfBlock);

		if ((void *)RelocEnd < *data || (void *)RelocEnd > ImageEnd) {
			Print(L"Reloc entry overflows binary\n");
			return EFI_UNSUPPORTED;
		}

		FixupBase = pecoff_image_address(*data, size, RelocBase->VirtualAddress);
		if (!FixupBase) {
			Print(L"Invalid fixupbase\n");
			return EFI_UNSUPPORTED;
		}

		while (Reloc < RelocEnd) {
			Fixup = FixupBase + (*Reloc & 0xFFF);
			switch ((*Reloc) >> 12) {
			case EFI_IMAGE_REL_BASED_ABSOLUTE:
				break;

			case EFI_IMAGE_REL_BASED_HIGH:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16 = (UINT16) (*Fixup16 + ((UINT16) ((UINT32) Adjust >> 16)));
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_LOW:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16  = (UINT16) (*Fixup16 + (UINT16) Adjust);
				if (FixupData != NULL) {
					*(UINT16 *) FixupData = *Fixup16;
					FixupData             = FixupData + sizeof (UINT16);
				}
				break;

			case EFI_IMAGE_REL_BASED_HIGHLOW:
				Fixup32   = (UINT32 *) Fixup;
				*Fixup32  = *Fixup32 + (UINT32) Adjust;
				if (FixupData != NULL) {
					FixupData             = ALIGN_POINTER (FixupData, sizeof (UINT32));
					*(UINT32 *)FixupData  = *Fixup32;
					FixupData             = FixupData + sizeof (UINT32);
				}
				break;

			case EFI_IMAGE_REL_BASED_DIR64:
				Fixup64 = (UINT64 *) Fixup;
				*Fixup64 = *Fixup64 + (UINT64) Adjust;
				if (FixupData != NULL) {
					FixupData = ALIGN_POINTER (FixupData, sizeof(UINT64));
					*(UINT64 *)(FixupData) = *Fixup64;
					FixupData = FixupData + sizeof(UINT64);
				}
				break;

			default:
				Print(L"Unknown relocation\n");
				return EFI_UNSUPPORTED;
			}
			Reloc += 1;
		}
		RelocBase = (EFI_IMAGE_BASE_RELOCATION *) RelocEnd;
	}

	return EFI_SUCCESS;
}

#ifdef BUILD_EFI
EFI_STATUS
pecoff_check_mok(EFI_HANDLE image, CHAR16 *name)
{
	EFI_STATUS status;
	UINT8 hash[SHA256_DIGEST_SIZE];
	UINT8 *data;
	UINTN len;
	UINT32 attr;

	/* first check is MokSBState.  If we're in insecure mode, boot
	 * anyway regardless of dbx contents */
	status = get_variable_attr(L"MokSBState", &data, &len,
				   MOK_OWNER, &attr);
	if (status == EFI_SUCCESS) {
		UINT8 MokSBState = data[0];

		FreePool(data);
		if ((attr & EFI_VARIABLE_RUNTIME_ACCESS) == 0
		    && MokSBState)
			return EFI_SUCCESS;
	}

	status = sha256_get_pecoff_digest(image, name, hash);
	if (status != EFI_SUCCESS)
		return status;

	if (find_in_variable_esl(L"dbx", SIG_DB, hash, SHA256_DIGEST_SIZE)
	    == EFI_SUCCESS)
		/* MOK list cannot override dbx */
		goto check_tmplist;

	status = get_variable_attr(L"MokList", &data, &len, MOK_OWNER, &attr);
	if (status != EFI_SUCCESS)
		goto check_tmplist;
	FreePool(data);

	if (attr & EFI_VARIABLE_RUNTIME_ACCESS)
		goto check_tmplist;

	if (find_in_variable_esl(L"MokList", MOK_OWNER, hash, SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

 check_tmplist:
	status = get_variable_attr(L"tmpHashList", &data, &len, MOK_OWNER,
				   &attr);
	if (status == EFI_SUCCESS && attr == EFI_VARIABLE_BOOTSERVICE_ACCESS
	    && find_in_variable_esl(L"tmpHashList", MOK_OWNER, hash,
				    SHA256_DIGEST_SIZE) == EFI_SUCCESS)
		return EFI_SUCCESS;

	return EFI_SECURITY_VIOLATION;
}

EFI_STATUS
pecoff_execute_checked(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab, CHAR16 *name)
{
	EFI_STATUS status;
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *loadpath = NULL;
	CHAR16 *PathName = NULL;
	EFI_HANDLE h;
	EFI_FILE *file;

	status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
				   &IMAGE_PROTOCOL, &li);
	if (status != EFI_SUCCESS)
		return status;
	status = generate_path(name, li, &loadpath, &PathName);
	if (status != EFI_SUCCESS)
		return status;
	status = uefi_call_wrapper(BS->LoadImage, 6, FALSE, image,
				   loadpath, NULL, 0, &h);
	if (status == EFI_SECURITY_VIOLATION || status == EFI_ACCESS_DENIED)
		status = pecoff_check_mok(image, name);
	if (status != EFI_SUCCESS)
		/* this will fail if signature validation fails */
		return status;
	uefi_call_wrapper(BS->UnloadImage, 1, h);

	status = simple_file_open(image, name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS)
		return status;

	pecoff_execute_image(file, name, image, systab);
	simple_file_close(file);

	return status;
}

EFI_STATUS
pecoff_execute_image(EFI_FILE *file, CHAR16 *name, EFI_HANDLE image,
		     EFI_SYSTEM_TABLE *systab)
{
	UINTN DataSize;
	void *buffer;
	EFI_STATUS efi_status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	EFI_STATUS (EFIAPI *entry_point) (EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);

	efi_status = simple_file_read_all(file, &DataSize, &buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to read %s\n", name);
		return efi_status;
	}

	Print(L"Read %d bytes from %s\n", DataSize, name);
	efi_status = pecoff_read_header(&context, buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to read header\n");
		goto out;
	}

	efi_status = pecoff_relocate(&context, &buffer);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to relocate image\n");
		goto out;
	}

	entry_point = pecoff_image_address(buffer, context.ImageSize, context.EntryPoint);
	if (!entry_point) {
		Print(L"Invalid entry point\n");
		efi_status = EFI_UNSUPPORTED;
		goto out;
	}

	efi_status = uefi_call_wrapper(entry_point, 2, image, systab);

 out:
	FreePool(buffer);

	return efi_status;
}
#endif
