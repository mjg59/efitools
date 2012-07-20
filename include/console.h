EFI_INPUT_KEY
console_get_keystroke(void);
void
console_print_box_at(CHAR16 *str_arr[], int highlight, int start_col, int start_row, int size_cols, int size_rows, int offset);
void
console_print_box(CHAR16 *str_arr[], int highlight);
int
console_yes_no(CHAR16 *str_arr[]);
