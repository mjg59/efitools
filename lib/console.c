#include <efi/efi.h>
#include <efi/efilib.h>

#include <console.h>

static int min(int a, int b)
{
	if (a < b)
		return a;
	return b;
}

static int
count_lines(CHAR16 *str_arr[])
{
	int i = 0;

	while (str_arr[i])
		i++;
	return i;
}

static void
SetMem16(CHAR16 *dst, UINT32 n, CHAR16 c)
{
	int i;

	for (i = 0; i < n/2; i++) {
		dst[i] = c;
	}
}

EFI_INPUT_KEY
console_get_keystroke(void)
{
	EFI_INPUT_KEY key;
	UINTN EventIndex;

	uefi_call_wrapper(BS->WaitForEvent, 3, 1, &ST->ConIn->WaitForKey, &EventIndex);
	uefi_call_wrapper(ST->ConIn->ReadKeyStroke, 2, ST->ConIn, &key);

	return key;
}

void
console_print_box_at(CHAR16 *str_arr[], int highlight, int start_col, int start_row, int size_cols, int size_rows, int offset)
{
	int lines = count_lines(str_arr), i;
	SIMPLE_TEXT_OUTPUT_INTERFACE *co = ST->ConOut;
	UINTN rows, cols;
	CHAR16 *Line;

	if (lines == 0)
		return;

	uefi_call_wrapper(co->QueryMode, 4, co, co->Mode->Mode, &cols, &rows);

	/* last row on screen is unusable without scrolling, so ignore it */
	rows--;

	if (size_rows < 0)
		size_rows = rows + size_rows + 1;
	if (size_cols < 0)
		size_cols = cols + size_cols + 1;

	if (start_col < 0)
		start_col = (cols + start_col + 2)/2;
	if (start_row < 0)
		start_row = (rows + start_row + 2)/2;

	if (start_col > cols || start_row > rows) {
		Print(L"Starting Position (%d,%d) is off screen\n",
		      start_col, start_row);
		return;
	}
	if (size_cols + start_col > cols || size_rows + start_row > rows) {
		Print(L"Box (%d, %d, %d, %d) is too big for screen\n",
		      start_col, start_row, size_cols + start_col,
		      size_rows + start_row);
		return;
	}
	       
	if (lines > size_rows - 2) {
		Print(L"Too many lines in string (%d), screen is only %d\n",
		      lines, size_rows - 2);
		return;
	}

	Line = AllocatePool((size_cols+1)*sizeof(CHAR16));
	if (!Line) {
		Print(L"Failed Allocation\n");
		return;
	}

	SetMem16 (Line, size_cols * 2, BOXDRAW_HORIZONTAL);

	Line[0] = BOXDRAW_DOWN_RIGHT;
	Line[size_cols - 1] = BOXDRAW_DOWN_LEFT;
	Line[size_cols] = L'\0';
	uefi_call_wrapper(co->SetCursorPosition, 3, co, start_col, start_row);
	uefi_call_wrapper(co->OutputString, 2, co, Line);

	int start;
	if (offset == 0)
		/* middle */
		start = (size_rows - lines)/2 + start_row + offset;
	else if (offset < 0)
		/* from bottom */
		start = start_row + size_rows - lines + offset - 1;
	else
		/* from top */
		start = start_row + offset;
		

	for (i = start_row + 1; i < size_rows + start_row - 1; i++) {
		int line = i - start;

		SetMem16 (Line, size_cols*2, L' ');
		Line[0] = BOXDRAW_VERTICAL;
		Line[size_cols - 1] = BOXDRAW_VERTICAL;
		Line[size_cols] = L'\0';
		if (line >= 0 && line < lines) {
			CHAR16 *s = str_arr[line];
			int len = StrLen(s);
			int col = (size_cols - 2 - len)/2;

			if (col < 0)
				col = 0;

			CopyMem(Line + col + 1, s, min(len, size_cols - 2)*2);
		}
		if (line >= 0 && line == highlight) 
			uefi_call_wrapper(co->SetAttribute, 2, co, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
		uefi_call_wrapper(co->SetCursorPosition, 3, co, start_col, i);
		uefi_call_wrapper(co->OutputString, 2, co, Line);
		if (line >= 0 && line == highlight) 
			uefi_call_wrapper(co->SetAttribute, 2, co, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);

	}
	SetMem16 (Line, size_cols * 2, BOXDRAW_HORIZONTAL);
	Line[0] = BOXDRAW_UP_RIGHT;
	Line[size_cols - 1] = BOXDRAW_UP_LEFT;
	Line[size_cols] = L'\0';
	uefi_call_wrapper(co->SetCursorPosition, 3, co, start_col, i);
	uefi_call_wrapper(co->OutputString, 2, co, Line);

	FreePool (Line);

}

void
console_print_box(CHAR16 *str_arr[], int highlight)
{
	SIMPLE_TEXT_OUTPUT_MODE SavedConsoleMode;
	SIMPLE_TEXT_OUTPUT_INTERFACE *co = ST->ConOut;
	CopyMem(&SavedConsoleMode, co->Mode, sizeof(SavedConsoleMode));
	uefi_call_wrapper(co->EnableCursor, 2, co, FALSE);
	uefi_call_wrapper(co->SetAttribute, 2, co, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);

	console_print_box_at(str_arr, highlight, 0, 0, -1, -1, 0);

	console_get_keystroke();

	uefi_call_wrapper(co->EnableCursor, 2, co, SavedConsoleMode.CursorVisible);

	uefi_call_wrapper(co->EnableCursor, 2, co, SavedConsoleMode.CursorVisible);
	uefi_call_wrapper(co->SetCursorPosition, 3, co, SavedConsoleMode.CursorColumn, SavedConsoleMode.CursorRow);
	uefi_call_wrapper(co->SetAttribute, 2, co, SavedConsoleMode.Attribute);
}

static void
console_print_yes_no_box(int highlight)
{
	console_print_box_at((CHAR16 *[]) {
			L"No",
			L"Yes",
			NULL
				}, highlight, -8, -4, 8, 4, 0);
}


int
console_yes_no(CHAR16 *str_arr[])
{
	SIMPLE_TEXT_OUTPUT_MODE SavedConsoleMode;
	SIMPLE_TEXT_OUTPUT_INTERFACE *co = ST->ConOut;
	EFI_INPUT_KEY k;
	int yesno = 0;

	CopyMem(&SavedConsoleMode, co->Mode, sizeof(SavedConsoleMode));
	uefi_call_wrapper(co->EnableCursor, 2, co, FALSE);
	uefi_call_wrapper(co->SetAttribute, 2, co, EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE);

	console_print_box_at(str_arr, -1, 0, 0, -1, -1, 1);

	console_print_yes_no_box(yesno);
	do {
		k = console_get_keystroke();

		if (k.ScanCode == SCAN_UP && yesno == 1)
			yesno = 0;
		else if (k.ScanCode == SCAN_DOWN && yesno == 0)
			yesno = 1;
		console_print_yes_no_box(yesno);
	} while (!(k.ScanCode == SCAN_NULL
		   && k.UnicodeChar == CHAR_CARRIAGE_RETURN));

	uefi_call_wrapper(co->EnableCursor, 2, co, SavedConsoleMode.CursorVisible);

	uefi_call_wrapper(co->EnableCursor, 2, co, SavedConsoleMode.CursorVisible);
	uefi_call_wrapper(co->SetCursorPosition, 3, co, SavedConsoleMode.CursorColumn, SavedConsoleMode.CursorRow);
	uefi_call_wrapper(co->SetAttribute, 2, co, SavedConsoleMode.Attribute);

	return yesno;
}
