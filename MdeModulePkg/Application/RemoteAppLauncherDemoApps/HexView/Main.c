/*
    Remote App Launcher Demo App : Hex View


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.16 at Jiangchuan, Minhang, Shanghai

*/


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>

#include "./HexView.h"


#define RUN_AND_EXIT_ON_ERROR(action) \
  do { \
    if (EFI_ERROR(Status = action)) { \
      Print(L"Error on [%s]. %r\r\n", #action, Status); \
      goto END; \
    } \
  } while (FALSE)


typedef struct {
  SHELL_FILE_HANDLE File;
} HexViewData;


STATIC
INT32
HexViewRead (
  VOID *UntypedData
  )
{
  HexViewData *Data = (HexViewData *) UntypedData;
  UINTN BytesRead = 1;

  CHAR8 Buf[1];

  if (EFI_ERROR(ShellReadFile (Data->File, &BytesRead, Buf)) || !BytesRead) {
    return -1;  // EOF
  }

  return ((INT32) Buf[0]) & 0xFF;
}


STATIC
VOID
HexViewWrite (
  INT32 Ch,
  VOID *UntypedData
  )
{
  Print(L"%c", Ch);
  if (Ch == '\n')
    Print(L"\r");
}


EFI_STATUS
EFIAPI
ShellAppMain (
  IN UINTN     Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS Status;

  if (Argc < 2) {
    Print(L"Usage: %s [file] [Optional Flag: --upper-case (Pass anything to enable this flag)]\r\n", Argv[0]);
    return EFI_INVALID_PARAMETER;
  }

  BOOLEAN UpperCase = Argc >= 3;

  RUN_AND_EXIT_ON_ERROR(ShellInitialize());

  SHELL_FILE_HANDLE File;

  RUN_AND_EXIT_ON_ERROR(
    ShellOpenFileByName (Argv[1], &File, EFI_FILE_MODE_READ, 0)
  );


  HexViewData Data = {
    .File = File
  };


  hexView (UpperCase, HexViewRead, HexViewWrite, &Data);
  

  ShellCloseFile (&File);


END:
  return Status;
}

