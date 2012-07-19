EFI_STATUS
simple_file_open (EFI_HANDLE image, CHAR16 *name, EFI_FILE **file, UINT64 mode);
EFI_STATUS
simple_file_read_all(EFI_FILE *file, UINTN *size, void **buffer);
EFI_STATUS
simple_file_write_all(EFI_FILE *file, UINTN size, void *buffer);
void
simple_file_close(EFI_FILE *file);
EFI_STATUS
generate_path(CHAR16* name, EFI_LOADED_IMAGE *li, EFI_DEVICE_PATH **grubpath, CHAR16 **PathName);
