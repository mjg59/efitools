#include <efi.h>
#include <efilib.h>

#include <simple_file.h>
#include <efiauthenticated.h>

static EFI_GUID IMAGE_PROTOCOL = LOADED_IMAGE_PROTOCOL;
static EFI_GUID SIMPLE_FS_PROTOCOL = SIMPLE_FILE_SYSTEM_PROTOCOL;
static EFI_GUID FILE_INFO = EFI_FILE_INFO_ID;

EFI_STATUS
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
simple_file_open(EFI_HANDLE image, CHAR16 *name, EFI_FILE **file, UINT64 mode)
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
				       mode, 0);

 error:
	//if (PathName)
	//	FreePool(PathName);

	return efi_status;
}

EFI_STATUS
simple_dir_read_all(EFI_HANDLE *image, CHAR16 *name, EFI_FILE_INFO **entries,
		    int *count)
{
	EFI_FILE *file;
	EFI_STATUS status;
	char buf[4096];
	UINTN size = sizeof(buf);
	EFI_FILE_INFO *fi = (void *)buf;

	status = simple_file_open(image, name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS) {
		Print(L"failed to open file %s: %d\n", name, status);
		return status;
	}
	
	status = uefi_call_wrapper(file->GetInfo, 4, file, &FILE_INFO,
				   &size, fi);
	if (status != EFI_SUCCESS) {
		Print(L"Failed to get file info\n");
		goto out;
	}
	if ((fi->Attribute & EFI_FILE_DIRECTORY) == 0) {
		Print(L"Not a directory %s\n", name);
		status = EFI_INVALID_PARAMETER;
		goto out;
	}
	size = 0;
	*count = 0;
	if (!*entries)
		return EFI_OUT_OF_RESOURCES;
	for (;;) {
		int len = sizeof(buf);
		status = uefi_call_wrapper(file->Read, 3, file, &len, buf);
		if (status != EFI_SUCCESS || len == 0)
			break;
		(*count)++;
		size += len;
	}
	uefi_call_wrapper(file->SetPosition, 2, file, 0);
	Print(L"Size is %d\n", size);
	char *ptr = AllocatePool(size);
	*entries = (EFI_FILE_INFO *)ptr;
	int i;
	for (i = 0; i < *count; i++) {
		int len = size;
		uefi_call_wrapper(file->Read, 3, file, &len, ptr);
		ptr += len;
		size -= len;
	}
	status = EFI_SUCCESS;
 out:
	simple_file_close(file);
	if (status != EFI_SUCCESS && *entries) {
		FreePool(*entries);
		*entries = NULL;
	}
	return status;
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


EFI_STATUS
simple_file_write_all(EFI_FILE *file, UINTN size, void *buffer)
{
	EFI_STATUS efi_status;

	efi_status = uefi_call_wrapper(file->Write, 3, file, &size, buffer);

	return efi_status;
}

void
simple_file_close(EFI_FILE *file)
{
	uefi_call_wrapper(file->Close, 1, file);
}

EFI_STATUS
simple_dir_filter(EFI_HANDLE *image, CHAR16 *name, CHAR16 *filter,
		  CHAR16 ***result, int *count, EFI_FILE_INFO **entries)
{
	EFI_STATUS status;
	int tot, offs = StrLen(filter), i;
	EFI_FILE_INFO *next;
	void *ptr;
	
	*count = 0;

	status = simple_dir_read_all(image, name, entries, &tot);
	if (status != EFI_SUCCESS)
		goto out;
	ptr = next = *entries;

	Print(L"%d directory entries\n", tot);

	for (i = 0; i < tot; i++) {
		int len = StrLen(next->FileName);

		if (StrCmp(&next->FileName[len - offs], filter) == 0)
			(*count) ++;

		ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (len + 1)*sizeof(CHAR16);
		next = ptr;
	}
	*result = AllocatePool((*count) * sizeof(void *));
	Print(L"Got %d from filter\n", *count);

	*count = 0;
	ptr = next = *entries;

	for (i = 0; i < tot; i++) {
		int len = StrLen(next->FileName);

		if (StrCmp(&next->FileName[len - offs], filter) == 0)
			(*result)[(*count)++] = next->FileName;

		ptr += OFFSET_OF(EFI_FILE_INFO, FileName) + (len + 1)*sizeof(CHAR16);
		next = ptr;
	}
	status = EFI_SUCCESS;

 out:
	if (status != EFI_SUCCESS) {
		if (*entries)
			FreePool(*entries);
		*entries = NULL;
		if (*result)
			FreePool(*result);
		*result = NULL;
	}
	return status;
}
