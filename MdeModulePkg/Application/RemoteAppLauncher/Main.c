/*
    Remote App Launcher


    gongty [at] tongji [dot] edu [dot] cn

    created on 2024.12.6 at Jiangchuan, Minhang, Shanghai
*/


#include <Base.h>
#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/ShellLib.h>
#include <Library/TimerLib.h>
#include <Library/NetLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>

#include <Protocol/Dhcp4.h>
#include <Protocol/Tcp4.h>
#include <Protocol/ServiceBinding.h>


static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *mTextOut;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL *mTextIn;
// todo: static EFI_TCP4_PROTOCOL *mTcpConnection;
// todo: static EFI_TCP4_PROTOCOL *mTcpListener;






EFI_STATUS
EFIAPI
ShellAppMain (
  IN UINTN     Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gEfiSimpleTextOutProtocolGuid, NULL, (VOID **) &mTextOut);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't open Text Output Protocol: %r\n", Status));
    return Status;
  }

  Status = gBS->LocateProtocol (&gEfiSimpleTextInProtocolGuid, NULL, (VOID **) &mTextIn);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't open Text Input Protocol: %r\n", Status));
    return Status;
  }

  


  return EFI_SUCCESS;
}
