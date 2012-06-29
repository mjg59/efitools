#include <efi.h>
#include <efilib.h>

#include <simple_file.h>

static EFI_GUID IMAGE_PROTOCOL = LOADED_IMAGE_PROTOCOL;
static EFI_GUID SIMPLE_FS_PROTOCOL = SIMPLE_FILE_SYSTEM_PROTOCOL;
static EFI_GUID FILE_INFO = EFI_FILE_INFO_ID;

static EFI_STATUS
generate_path(CHAR16* name, EFI_LOADED_IMAGE *li, EFI_DEVICE_PATH **grubpath, CHAR16 **PathName)
{
	EFI_DEVICE_PATH *devpath;
	EFI_HANDLE device;
	FILEPATH_DEVICE_PATH *FilePath;
	int len;
	unsigned int pathlen = 0;
	EFI_STATUS efi_status = EFI_SUCCESS;

	device = li->DeviceHandle;
	devpath = li->FilePath;

	while (!IsDevicePathEnd(devpath) &&
	       !IsDevicePathEnd(NextDevicePathNode(devpath))) {
		FilePath = (FILEPATH_DEVICE_PATH *)devpath;
		len = StrLen(FilePath->PathName);

		pathlen += len;

		if (len == 1 && FilePath->PathName[0] == '\\') {
			devpath = NextDevicePathNode(devpath);
			continue;
		}

		/* If no leading \, need to add one */
		if (FilePath->PathName[0] != '\\')
			pathlen++;

		/* If trailing \, need to strip it */
		if (FilePath->PathName[len-1] == '\\')
			pathlen--;

		devpath = NextDevicePathNode(devpath);
	}

	*PathName = AllocatePool(pathlen + StrLen(name));

	if (!*PathName) {
		Print(L"Failed to allocate path buffer\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto error;
	}

	*PathName[0] = '\0';
	devpath = li->FilePath;

	while (!IsDevicePathEnd(devpath) &&
	       !IsDevicePathEnd(NextDevicePathNode(devpath))) {
		CHAR16 *tmpbuffer;
		FilePath = (FILEPATH_DEVICE_PATH *)devpath;
		len = StrLen(FilePath->PathName);

		if (len == 1 && FilePath->PathName[0] == '\\') {
			devpath = NextDevicePathNode(devpath);
			continue;
		}

		tmpbuffer = AllocatePool(len + 1);

		if (!tmpbuffer) {
			Print(L"Unable to allocate temporary buffer\n");
			return EFI_OUT_OF_RESOURCES;
		}

		StrCpy(tmpbuffer, FilePath->PathName);

		/* If no leading \, need to add one */
		if (tmpbuffer[0] != '\\')
			StrCat(*PathName, L"\\");

		/* If trailing \, need to strip it */
		if (tmpbuffer[len-1] == '\\')
			tmpbuffer[len=1] = '\0';

		StrCat(*PathName, tmpbuffer);
		FreePool(tmpbuffer);
		devpath = NextDevicePathNode(devpath);
	}

	StrCat(*PathName, name);

	*grubpath = FileDevicePath(device, *PathName);

error:
	return efi_status;
}

EFI_STATUS
simple_file_open (EFI_HANDLE image, CHAR16 *name, EFI_FILE **file)
{
	EFI_STATUS efi_status;
	EFI_HANDLE device;
	EFI_FILE_IO_INTERFACE *drive;
	EFI_LOADED_IMAGE *li;
	EFI_DEVICE_PATH *loadpath = NULL;
	EFI_FILE *root;
	CHAR16 *PathName = NULL;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, image,
				       &IMAGE_PROTOCOL, &li);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to init image protocol\n");
		return efi_status;
	}

	efi_status = generate_path(name, li, &loadpath, &PathName);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to generate load path for %s\n", name);
		goto error;
	}
	Print(L"Path Name is %s\n", PathName);

	device = li->DeviceHandle;

	efi_status = uefi_call_wrapper(BS->HandleProtocol, 3, device,
				       &SIMPLE_FS_PROTOCOL, &drive);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Unable to find simple file protocol\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(drive->OpenVolume, 2, drive, &root);

	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to open drive volume\n");
		goto error;
	}

	efi_status = uefi_call_wrapper(root->Open, 5, root, file, PathName,
				       EFI_FILE_MODE_READ, 0);

 error:
	//if (PathName)
	//	FreePool(PathName);

	return efi_status;
}

EFI_STATUS
simple_file_read_all(EFI_FILE *file, UINTN *size, void **buffer)
{
	EFI_STATUS efi_status;
	EFI_FILE_INFO *fi;
	char buf[1024];

	*size = sizeof(buf);
	fi = (void *)buf;
	

	efi_status = uefi_call_wrapper(file->GetInfo, 4, file, &FILE_INFO,
				       size, fi);
	if (efi_status != EFI_SUCCESS) {
		Print(L"Failed to get file info\n");
		return efi_status;
	}

	*size = fi->FileSize;
	Print(L"FILE SIZE IS %d\n", *size);
	*buffer = AllocatePool(*size);
	if (!*buffer) {
		Print(L"Failed to allocate buffer of size %d\n", *size);
		return EFI_OUT_OF_RESOURCES;
	}
	efi_status = uefi_call_wrapper(file->Read, 3, file, size, *buffer);

	return efi_status;
}
