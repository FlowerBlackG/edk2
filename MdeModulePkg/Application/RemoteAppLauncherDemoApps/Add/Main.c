/*
    Remote App Launcher Demo App : Add


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.16 at Jiangchuan, Minhang, Shanghai

*/


#include <Base.h>
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>


#define RUN_AND_EXIT_ON_ERROR(action) \
  do { \
    if (EFI_ERROR(Status = action)) { \
      Print(L"Error on [%s]. %r\r\n", #action, Status); \
      goto END; \
    } \
  } while (FALSE)



STATIC
EFIAPI
EFI_STATUS
ReadUserInputPool (
  OUT CHAR16 *Unicode,
  IN BOOLEAN Echo
  )
{
  EFI_STATUS Status;
  EFI_INPUT_KEY Key;

  if (!Unicode)
    return EFI_INVALID_PARAMETER;

  do {
    Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    
    if (EFI_ERROR(Status) && Status != EFI_NOT_READY)
      return Status;
  } while (EFI_ERROR(Status));

  *Unicode = Key.UnicodeChar;
  return Status;
}


STATIC
EFIAPI
EFI_STATUS
ReadInt (
  OUT INT32 *Value,
  IN BOOLEAN Echo
  )
{
  EFI_STATUS Status;

  INT32 ValueRead = 0;
  CHAR16 Ch;
  BOOLEAN LeadingsIgnored = FALSE;

  while (!EFI_ERROR(Status = ReadUserInputPool(&Ch, Echo))) {

    if (Echo) {
      Print(L"%c", Ch);
    
      if (Ch == L'\r')
        AsciiPrint("\n");
      else if (Ch == L'\n')
        AsciiPrint("\r");
    }

    if (Ch >= L'0' && Ch <= L'9') {
    
      LeadingsIgnored = TRUE;
      ValueRead = ValueRead * 10 + (Ch - L'0');
    
    } else if (LeadingsIgnored) {
    
      break;
    
    } else {

      continue;
    
    }
  }

  if (!EFI_ERROR(Status))
    *Value = ValueRead;

  return Status;
}


EFI_STATUS
EFIAPI
ShellAppMain (
  IN UINTN     Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS Status;

  if (Argc >= 2 && StrCmp (Argv[1], L"--help") == 0) {
    Print(L"Usage: %s [Optional Flag: Pass anything except --help to disable echo]\r\n", Argv[0]);
    return EFI_SUCCESS;
  }

  BOOLEAN Echo = Argc < 2;

  INT32 Values[2];

  RUN_AND_EXIT_ON_ERROR(ReadInt(Values + 0, Echo));
  RUN_AND_EXIT_ON_ERROR(ReadInt(Values + 1, Echo));

  Print(L"%d + %d = %d\r\n", Values[0], Values[1], Values[0] + Values[1]);

END:
  return Status;
}

