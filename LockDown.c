#include <efi.h>
#include <efilib.h>
#include "efiauthenticated.h"
#include "PK.h"
#include "KEK.h"

EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;

EFI_STATUS
CreatePkX509SignatureList (
  IN	UINT8			    *X509Data,
  IN	UINTN			    X509DataSize,
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
  PkCertData->SignatureOwner = (EFI_GUID)EFI_GLOBAL_VARIABLE;  
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
  
  if (Payload != NULL) {
    FreePool(Payload);
  }
  
  *DataSize = DescriptorSize + PayloadSize;
  *Data     = NewData;
  return EFI_SUCCESS;
}

EFI_STATUS
SetSecureVariable(CHAR16 *var, UINT8 *Data, UINTN len)
{
	EFI_SIGNATURE_LIST *Cert;
	UINTN DataSize;
	EFI_STATUS efi_status;

	efi_status = CreatePkX509SignatureList(Data, len, &Cert);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to create %s certificate %d\n", var, efi_status);
		return efi_status;
	}

	DataSize = Cert->SignatureListSize;
	Print(L"Created %s Cert of size %d\n", var, DataSize);
	efi_status = CreateTimeBasedPayload(&DataSize, (UINT8 **)&Cert);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to create time based payload %d\n", efi_status);
		return efi_status;
	}

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, var, &GV_GUID,
				       EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS 
				       | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
				       DataSize, Cert);

	return efi_status;
}

EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	char Data[4096];
	UINT8 SecureBoot, SetupMode;
	UINTN DataSize = sizeof(SetupMode);

	InitializeLib(image, systab);

	efi_status = uefi_call_wrapper(RT->GetVariable, 5, L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");
		return EFI_SUCCESS;
	}

	if (!SetupMode) {
		Print(L"Platform is not in Setup Mode, cannot install Keys\n");
		return EFI_SUCCESS;
	}

	Print(L"Platform is in Setup Mode\n");

	efi_status = SetSecureVariable(L"PK", PK_cer, PK_cer_len);
	efi_status = SetSecureVariable(L"KEK", KEK_cer, KEK_cer_len);

	/* now enable secure boot */

	efi_status = uefi_call_wrapper(RT->SetVariable, 5, L"SecureBoot", &GV_GUID,
				       EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
				       sizeof(SecureBoot), &SecureBoot);

	return EFI_SUCCESS;
	
}
