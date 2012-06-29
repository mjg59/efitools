EFI_STATUS
simple_file_open (EFI_HANDLE image, CHAR16 *name, EFI_FILE **file);
EFI_STATUS
simple_file_read_all(EFI_FILE *file, UINTN *size, void **buffer);
