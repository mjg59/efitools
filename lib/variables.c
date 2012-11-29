/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 *
 * Portions of this file are a direct cut and paste from Tianocore
 * (http://tianocore.sf.net)
 *
 *  SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigImpl.c
 *
 * Copyright (c) 2011 - 2012, Intel Corporation. All rights reserved.<BR>
 * This program and the accompanying materials
 * are licensed and made available under the terms and conditions of the BSD License
 * which accompanies this distribution.  The full text of the license may be found 
 * at
 * http://opensource.org/licenses/bsd-license.php
 *
 * THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
 * WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
 * 
 */
#include <efi.h>
#include <efilib.h>

#include <efiauthenticated.h>

#include <variables.h>
#include <guid.h>
#include <console.h>

EFI_STATUS
CreatePkX509SignatureList (
  IN	UINT8			    *X509Data,
  IN	UINTN			    X509DataSize,
  IN	EFI_GUID		    owner,
  OUT   EFI_SIGNATURE_LIST          **PkCert 
  )
{
  EFI_STATUS              Status = EFI_SUCCESS;  
  EFI_SIGNATURE_DATA      *PkCertData;

  PkCertData = NULL;

  //
  // Allocate space for PK certificate list and initialize it.
  // Create PK database entry with SignatureHeaderSize equals 0.
  //
  *PkCert = (EFI_SIGNATURE_LIST*) AllocateZeroPool (
              sizeof(EFI_SIGNATURE_LIST) + sizeof(EFI_SIGNATURE_DATA) - 1
              + X509DataSize
              );
  if (*PkCert == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  (*PkCert)->SignatureListSize   = (UINT32) (sizeof(EFI_SIGNATURE_LIST) 
                                    + sizeof(EFI_SIGNATURE_DATA) - 1
                                    + X509DataSize);
  (*PkCert)->SignatureSize       = (UINT32) (sizeof(EFI_SIGNATURE_DATA) - 1 + X509DataSize);
  (*PkCert)->SignatureHeaderSize = 0;
  (*PkCert)->SignatureType = EFI_CERT_X509_GUID;

  PkCertData                     = (EFI_SIGNATURE_DATA*) ((UINTN)(*PkCert) 
                                                          + sizeof(EFI_SIGNATURE_LIST)
                                                          + (*PkCert)->SignatureHeaderSize);
  PkCertData->SignatureOwner = owner;  
  //
  // Fill the PK database with PKpub data from X509 certificate file.
  //  
  CopyMem (&(PkCertData->SignatureData[0]), X509Data, X509DataSize);
  
ON_EXIT:
  
  if (EFI_ERROR(Status) && *PkCert != NULL) {
    FreePool (*PkCert);
    *PkCert = NULL;
  }
  
  return Status;
}

EFI_STATUS
CreateTimeBasedPayload (
  IN OUT UINTN            *DataSize,
  IN OUT UINT8            **Data
  )
{
  EFI_STATUS                       Status;
  UINT8                            *NewData;
  UINT8                            *Payload;
  UINTN                            PayloadSize;
  EFI_VARIABLE_AUTHENTICATION_2    *DescriptorData;
  UINTN                            DescriptorSize;
  EFI_TIME                         Time;
  EFI_GUID efi_cert_type = EFI_CERT_TYPE_PKCS7_GUID;
  
  if (Data == NULL || DataSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  //
  // In Setup mode or Custom mode, the variable does not need to be signed but the 
  // parameters to the SetVariable() call still need to be prepared as authenticated
  // variable. So we create EFI_VARIABLE_AUTHENTICATED_2 descriptor without certificate
  // data in it.
  //
  Payload     = *Data;
  PayloadSize = *DataSize;
  
  DescriptorSize    = OFFSET_OF(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo) + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
  NewData = (UINT8*) AllocateZeroPool (DescriptorSize + PayloadSize);
  if (NewData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  if ((Payload != NULL) && (PayloadSize != 0)) {
    CopyMem (NewData + DescriptorSize, Payload, PayloadSize);
  }

  DescriptorData = (EFI_VARIABLE_AUTHENTICATION_2 *) (NewData);

  ZeroMem (&Time, sizeof (EFI_TIME));
  Status = uefi_call_wrapper(RT->GetTime,2, &Time, NULL);
  if (EFI_ERROR (Status)) {
    FreePool(NewData);
    return Status;
  }
  Time.Pad1       = 0;
  Time.Nanosecond = 0;
  Time.TimeZone   = 0;
  Time.Daylight   = 0;
  Time.Pad2       = 0;
  CopyMem (&DescriptorData->TimeStamp, &Time, sizeof (EFI_TIME));
 
  DescriptorData->AuthInfo.Hdr.dwLength         = OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  DescriptorData->AuthInfo.Hdr.wRevision        = 0x0200;
  DescriptorData->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  DescriptorData->AuthInfo.CertType =  efi_cert_type;
 
  /* we're expecting an EFI signature list, so don't free the input since
   * it might not be in a pool */
#if 0
  if (Payload != NULL) {
    FreePool(Payload);
  }
#endif
  
  *DataSize = DescriptorSize + PayloadSize;
  *Data     = NewData;
  return EFI_SUCCESS;
}

EFI_STATUS
SetSecureVariable(CHAR16 *var, UINT8 *Data, UINTN len, EFI_GUID owner, UINT32 options, int createtimebased)
{
	EFI_SIGNATURE_LIST *Cert;
	UINTN DataSize;
	EFI_STATUS efi_status;

	if (createtimebased) {
		efi_status = CreatePkX509SignatureList(Data, len, owner, &Cert);
		if (efi_status != EFI_SUCCESS) {
			Print(L"Failed to create %s certificate %d\n", var, efi_status);
			return efi_status;
			DataSize = Cert->SignatureListSize;
		}
	} else {
		/* we expect an efi signature list rather than creating it */
		Cert = (EFI_SIGNATURE_LIST *)Data;
		DataSize = len;
	}
	Print(L"Created %s Cert of size %d\n", var, DataSize);
	efi_status = CreateTimeBasedPayload(&DataSize, (UINT8 **)&Cert);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to create time based payload %d\n", efi_status);
		return efi_status;
	}

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, var, &owner,
				       EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | options,
				       DataSize, Cert);

	return efi_status;
}

UINT64
GetOSIndications(void)
{
	UINT64 indications;
	UINTN DataSize = sizeof(indications);
	EFI_STATUS efi_status;

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"OsIndicationsSupported", &GV_GUID, NULL, &DataSize, &indications);
	if (efi_status != EFI_SUCCESS)
		return 0;

	return indications;
}

EFI_STATUS
SETOSIndicationsAndReboot(UINT64 indications)
{
	UINTN DataSize = sizeof(indications);
	EFI_STATUS efi_status;

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"OsIndications",
				       &GV_GUID,
				       EFI_VARIABLE_NON_VOLATILE
				       | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				       DataSize, &indications);

	if (efi_status != EFI_SUCCESS) {
		Print(L"GetVariable returned %d\n", efi_status);
		console_get_keystroke();
		return efi_status;
	}

	uefi_call_wrapper(RT->ResetSystem, 4, EfiResetWarm, EFI_SUCCESS, 0, NULL);
	/* does not return */

	return EFI_SUCCESS;
}
