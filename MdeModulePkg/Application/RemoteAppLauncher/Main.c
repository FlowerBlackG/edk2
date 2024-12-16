/*
    Remote App Launcher


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.6 at Jiangchuan, Minhang, Shanghai

    Reference:
      https://github.com/vinxue/TcpTransport/blob/master/TcpTransport.c
*/


#include <Base.h>
#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
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

#include <Library/TcpIoLib.h>

#include "./Utils.h"
#include "./VesperProtocol.h"
#include "./HexView.h"


STATIC EFI_SHELL_PARAMETERS_PROTOCOL *ShellParameters = NULL;

STATIC EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *TextOut = NULL;
STATIC EFI_SIMPLE_TEXT_INPUT_PROTOCOL *TextIn = NULL;

STATIC EFI_HANDLE NetDeviceHandle = NULL;

STATIC TCP_IO *TcpIo = NULL;

STATIC EFI_HANDLE AppImageHandle = NULL;
STATIC EFI_SYSTEM_TABLE *AppSystemTable = NULL;


struct {

  // Actions

  BOOLEAN ActionUsage;
  BOOLEAN ActionListFiles;
  BOOLEAN ActionLoadFile;

  
  BOOLEAN IpAddrSet;
  EFI_IPv4_ADDRESS Ip4Addr;

  BOOLEAN PortSet;
  UINT16 Port;

  BOOLEAN FileIdSet;
  UINT64 FileId;

  BOOLEAN SaveBinaryToSet;
  CHAR16 *SaveBinaryTo;

  BOOLEAN CliSet;
  CHAR16 *Cli;

  BOOLEAN RemoveBinaryAfterExecution;

} STATIC CliArgs;



STATIC
VOID
EFIAPI
Usage (
  CONST CHAR16 *ExePath
  )
{
  Print(ExePath);
  Print(L"\r\n\r\nRemote App Launcher\r\n\r\n");
  Print(L"Check https://github.com/FlowerBlackG/edk2/tree/master/MdeModulePkg/Application/RemoteAppLauncher/Usage.md for detailed usage.\r\n\r\n");
}


STATIC
EFI_STATUS
EFIAPI
ParseCli (
  IN UINTN Argc,
  IN CHAR16 **Argv
  )
{
  ZeroMem ( &CliArgs, sizeof(CliArgs) );
  UINTN Pos = 1;
  

  while (Pos < Argc) {

    CONST CHAR16 *Arg = Argv[Pos++];  // Consumes one arg.
    if (
      StrCmp(Arg, L"-?") == 0 || 
      StrCmp(Arg, L"-h") == 0 || 
      StrCmp(Arg, L"--help") == 0 ||
      StrCmp(Arg, L"--usage") == 0
      )
    {
      CliArgs.ActionUsage = TRUE;
      return EFI_SUCCESS;
    }


    if (StrCmp(Arg, L"--list") == 0) {
      CliArgs.ActionListFiles = TRUE;
      continue;
    }


    if (StrCmp(Arg, L"--load") == 0) {
      CliArgs.ActionLoadFile = TRUE;

      if (Pos == Argc) {
        Print(L"No file id for --load !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CONST CHAR16 *FileIdStr = Argv[Pos++];
      CliArgs.FileId = (UINT16) char16_to_int(FileIdStr);  // Might be buggy.
      CliArgs.FileIdSet = TRUE;

      continue;
    }


    if (StrCmp(Arg, L"--port") == 0) {
      if (Pos == Argc) {
        Print(L"No value for --port !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CONST CHAR16 *PortStr = Argv[Pos++];
      CliArgs.Port = (UINT16) char16_to_int(PortStr);  // Might be buggy.
      CliArgs.PortSet = TRUE;

      continue;
    }


    if (StrCmp(Arg, L"--ip") == 0) {

      if (Pos == Argc) {
        Print(L"No value for --ip !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CONST CHAR16 *IpStr = Argv[Pos++];
      EFI_STATUS Status = NetLibStrToIp4(IpStr, &CliArgs.Ip4Addr);
      if (EFI_ERROR(Status)) {
        Print(L"Failed to parse IP address !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CliArgs.IpAddrSet = TRUE;

      continue;
    }

    
    if (StrCmp(Arg, L"--remove-binary-after-execution") == 0) {
      CliArgs.RemoveBinaryAfterExecution = TRUE;
      continue;
    }


    if (StrCmp(Arg, L"--save-binary-to") == 0) {

      if (Pos == Argc) {
        Print(L"No value for --save-binary-to !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CliArgs.SaveBinaryTo = Argv[Pos++];
      CliArgs.SaveBinaryToSet = TRUE;

      continue;
    }

    
    if (StrCmp(Arg, L"--cli") == 0) {

      if (Pos == Argc) {
        Print(L"No value for --cli !\r\n");
        return EFI_INVALID_PARAMETER;
      }

      CliArgs.Cli = Argv[Pos++];
      CliArgs.CliSet = TRUE;

      continue;
    }


  }  // while (Pos < Argc)

  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
FindArgcAndArgv (
  OUT UINTN *Argc,
  OUT CHAR16 ***Argv
  )
{
  EFI_STATUS Status = EFI_SUCCESS;


  Status = AppSystemTable->BootServices->OpenProtocol (
    AppImageHandle,
    &gEfiShellParametersProtocolGuid,
    (VOID **) &ShellParameters,
    AppImageHandle,
    NULL,
    EFI_OPEN_PROTOCOL_GET_PROTOCOL
  );

  
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed to open efi shell params protocol! %r\n", Status));
    return Status;
  }


  *Argc = ShellParameters->Argc;
  *Argv = ShellParameters->Argv;

  return Status;
}


STATIC
EFI_STATUS
EFIAPI
PrepareTextIOProtocols ()
{
  EFI_STATUS Status;

  Status = gBS->LocateProtocol (&gEfiSimpleTextOutProtocolGuid, NULL, (VOID **) &TextOut);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't open Text Output Protocol: %r\n", Status));
    return Status;
  }

  Status = gBS->LocateProtocol (&gEfiSimpleTextInProtocolGuid, NULL, (VOID **) &TextIn);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't open Text Input Protocol: %r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
EFIAPI
PrepareNetDeviceHandle ()
{
  EFI_STATUS Status;

  // Locate the service binding protocol.

  UINTN NumHandles;
  EFI_HANDLE *HandleBuffer;

  Status = gBS->LocateHandleBuffer(
    ByProtocol,
    &gEfiTcp4ServiceBindingProtocolGuid,
    NULL,
    &NumHandles,
    &HandleBuffer
  );

  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "Couldn't find TCP4 service binding: %r\n", Status));
    return Status;
  }

  DEBUG((DEBUG_INFO, "%d TCP4 service binding(s) found.\n", NumHandles));

  if (NumHandles == 0) {
    DEBUG((DEBUG_ERROR, "Couldn't find TCP4 service bindings.\n"));
    return EFI_NOT_FOUND;
  }


  // Just use the first network device.
  NetDeviceHandle = HandleBuffer[0];

  return EFI_SUCCESS;
}



STATIC
VOID
EFIAPI
BuildTcp4ConfigData (
  IN OUT EFI_TCP4_CONFIG_DATA *ConfigData,
  IN EFI_IPv4_ADDRESS *RemoteAddress,
  IN UINT16 RemotePort
  ) 
{

  ConfigData->TimeToLive = 255;  // Max value
  ConfigData->TypeOfService = 8;  // High throughout.

  ConfigData->ControlOption = NULL;

  ConfigData->AccessPoint.UseDefaultAddress = TRUE;  // Use DHCP.
  ConfigData->AccessPoint.ActiveFlag = TRUE;

  IP4_COPY_ADDRESS(&ConfigData->AccessPoint.RemoteAddress, RemoteAddress);
  ConfigData->AccessPoint.RemotePort = RemotePort;
  
  IP4_COPY_ADDRESS(&ConfigData->AccessPoint.StationAddress, &mZeroIp4Addr);
  IP4_COPY_ADDRESS(&ConfigData->AccessPoint.SubnetMask, &mZeroIp4Addr);
  ConfigData->AccessPoint.StationPort = 0;  // Use any port.

}



/**
 * The caller is responsible for freeing TcpIo (by calling DestroySocket) 
 * when result is EFI_SUCCESS.
 */
STATIC
EFI_STATUS
EFIAPI
CreateSocket (
  IN EFI_IPv4_ADDRESS *Addr,
  IN UINT16 Port,
  OUT TCP_IO **TcpIo
  )
{

  TCP_IO *Socket = AllocatePool (sizeof (TCP_IO));
  if (!Socket)
    return EFI_OUT_OF_RESOURCES;

  
  TCP_IO_CONFIG_DATA TcpIoConfData;
  ZeroMem (&TcpIoConfData, sizeof(TCP_IO_CONFIG_DATA));

  EFI_TCP4_CONFIG_DATA Tcp4ConfigData;

  BuildTcp4ConfigData (
    &Tcp4ConfigData,
    Addr,
    Port
  );


  EFI_STATUS Status = TcpIoCreateSocket(
    gImageHandle,
    NetDeviceHandle,
    TCP_VERSION_4,
    &TcpIoConfData,
    Socket
  );

  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((DEBUG_INFO, "Socket created. \n"));

  EFI_TCP4_PROTOCOL *Tcp4 = Socket->Tcp.Tcp4;


  Tcp4->Configure(Tcp4, NULL);  // Reset before reconfigure.

  if (EFI_ERROR(Status = Tcp4->Configure(Tcp4, &Tcp4ConfigData))) {
    goto END;
  }


END:

  if (EFI_ERROR(Status)) {
    TcpIoDestroySocket (Socket);
    FreePool (Socket);
  } 
  else {
    *TcpIo = Socket;
  }

  return Status;
}


STATIC
VOID
EFIAPI
DestroySocket (
  IN TCP_IO *TcpIo
  )
{
  TcpIoDestroySocket (TcpIo);
  FreePool (TcpIo);
}


STATIC
VOID
EFIAPI
CleanUp()
{
  if (TcpIo) {
    DestroySocket(TcpIo);
    TcpIo = NULL;
  }
}


/**
 * The caller is responsible for freeing ResponseMsg (by calling FreePool) 
 * when result is EFI_SUCCESS.
 */
STATIC
EFI_STATUS
EFIAPI
VesperProtocolRecvResponseAndDealError (
  IN TCP_IO *TcpIo,
  OUT VESPER_PROTOCOL_RESPONSE **ResponseMsg
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  VESPER_PROTOCOL_RESPONSE *Response = NULL;

  if (EFI_ERROR(Status = VesperProtocolRecvResponse(TcpIo, &Response))) {
    Print(L"Failed to get response from remote!\r\n");
    return Status;
  }

  if (Response->Body.Code) {
    
    CHAR8 *Buf = AllocatePool (Response->Body.MsgLen + 1);
    if (!Buf) {
      FreePool (Response);
      return EFI_OUT_OF_RESOURCES;
    }
    
    Buf[Response->Body.MsgLen] = '\0';
    CopyMem (Buf, Response->Body.Msg, Response->Body.MsgLen);
    AsciiPrint("%a\r\n", Buf);
    
    FreePool (Buf);
    
    goto END;
  }


END:

  if (EFI_ERROR(Status)) {
    FreePool (Response);
  } else {
    *ResponseMsg = Response;
  }

  return Status;
}


STATIC
EFI_STATUS
EFIAPI
DoListFiles ()
{
  EFI_STATUS Status = EFI_SUCCESS;

  if (EFI_ERROR(Status = VesperProtocolSendListFilesMsg(TcpIo))) {
    Print(L"Failed to send list files msg to remote!\r\n");
    return Status;
  }


  VESPER_PROTOCOL_RESPONSE *Response = NULL;

  if (EFI_ERROR(Status = VesperProtocolRecvResponseAndDealError(TcpIo, &Response))) {
    return Status;
  }


  // Print file ids and names.

  CONST CHAR8 *PtrEnd = (CONST CHAR8 *) &Response->Body.Msg[Response->Body.MsgLen];
  CHAR8 *Ptr = (CHAR8 *) Response->Body.Msg;


  while (Ptr < PtrEnd) {

    Print(L"%llu : ", htonq (*(UINT64 *) (Ptr)));
    Ptr += sizeof (UINT64);

    Ptr += AsciiPrint("%a", Ptr) + 1;
    
    Print(L"\r\n");
  }


  if (Response) {
    FreePool (Response);
    Response = NULL;
  }

  return Status;
}



/**
 * The caller is responsible for freeing Path (by calling FreePool) 
 * when result is EFI_SUCCESS.
 */
STATIC
EFI_STATUS
EFIAPI
FindPathToSaveLoadedBinary (
  OUT CHAR16 **Path
  )
{
  if (CliArgs.SaveBinaryToSet) {
    UINTN Len = StrLen (CliArgs.SaveBinaryTo);
    *Path = AllocatePool (sizeof(CHAR16) * (Len + 1));
    
    if (!Path)
      return EFI_OUT_OF_RESOURCES;

    CopyMem (*Path, CliArgs.SaveBinaryTo, sizeof(CHAR16) * (Len + 1));
    return EFI_SUCCESS;
  }


  CONST CHAR16 *FallbackFilePaths[] = {
    L"d7c9b44f-60b5-4ac8-919c-ea1f7a112b94.efi",
    L"b58a777e-a5bb-4c89-a0ca-4467c103a002.efi",
    L"e3dd8ab2-4251-407f-8ae3-36df9cab1279.efi",
    L"844cfc62-c7aa-4d49-82de-67ac5871f33a.efi",
    L"39774e4b-1d96-474a-bb69-5e32ea17221a.efi",
    L"74542af7-2c22-47de-9e43-be3eaf3971ab.efi",
    L"55dbb818-c3ee-4286-90ac-bcc96739bce8.efi",
    L"25d51515-3897-445e-bf16-d35a9dd8b698.efi",
    L"954ccacf-1673-4112-8326-2b4c8bb5b350.efi",
    L"23caf1e5-424f-4bd4-bde3-b36a02c923ee.efi",
    L"3e9d8396-f6b3-4f9b-b603-9175843123b4.efi"
  };

  CONST UINTN CandidateCount = sizeof(FallbackFilePaths) / sizeof(FallbackFilePaths[0]);

  for (UINTN i = 0; i < CandidateCount; i++) {
    CONST CHAR16 *FileName = FallbackFilePaths[i];
    
    if ( ShellFileExists(FileName) == EFI_SUCCESS )
      continue;

    UINTN Len = StrLen (FileName);
    *Path = AllocatePool (sizeof(CHAR16) * (Len + 1));

    if (!Path)
      return EFI_OUT_OF_RESOURCES;

    CopyMem (*Path, FileName, sizeof(CHAR16) * (Len + 1));
    return EFI_SUCCESS;
  }


  Print(
    L"Failed to find a place to save loaded binary. "
    "Perhaps you should specify --save-binary-to manually.\r\n"
  );

  return EFI_LOAD_ERROR;
}


STATIC
EFI_STATUS
EFIAPI
SaveEfiAppBinaryAndExecute (
  IN UINT8 *Binary,
  IN UINTN BinarySize,
  IN CHAR16 *FilePath,
  IN BOOLEAN RemoveFileAfterExecution,
  IN CHAR16 *Cli OPTIONAL
  )
{
  if (!Binary || !FilePath || !BinarySize)
    return EFI_INVALID_PARAMETER;

  EFI_STATUS Status;

  SHELL_FILE_HANDLE File;

  Status = ShellOpenFileByName (
    FilePath, 
    &File,
    EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, 
    0
  );

  if (EFI_ERROR(Status)) {
    Print(L"Failed to open file! %r\r\n", Status);
    goto END;
  }
  
  
  UINT64 FileSize = BinarySize;
  if (EFI_ERROR(Status = ShellWriteFile(File, &FileSize, Binary)) || FileSize != BinarySize) {
    Print(L"Failed to save binary to: %s\r\n", FilePath);
    goto END;
  }


  if (EFI_ERROR(Status = ShellFlushFile (File))) {
    Print(L"Failed to flush file! %r\r\n", Status);
    goto END;
  }
  

  if (EFI_ERROR(Status = ShellCloseFile (&File))) {
    Print(L"Failed to close file! %r\r\n", Status);
    goto END;
  }
  

  // Make command.

  UINTN FilePathLen = StrLen (FilePath);
  UINTN CliLen = Cli ? StrLen (Cli) : 0;

  // File + Blank between file and cli + cli
  UINTN CommandLen = FilePathLen + !!CliLen + CliLen;

  CHAR16 *Command = AllocatePool (sizeof (CHAR16) * (CommandLen + 1));
  if (!Command) {
    Status = EFI_OUT_OF_RESOURCES;
    goto END;
  }

  Command[FilePathLen] = L' ';
  Command[CommandLen] = L'\0';
  CopyMem (Command, FilePath, FilePathLen * sizeof (CHAR16));
  CopyMem (Command + FilePathLen + 1, Cli, CliLen * sizeof (CHAR16));

  
  EFI_STATUS ChildStatus;

  // Vulnerability: Sub-process can modify parent's environment!
  Status = ShellExecute (&AppImageHandle, Command, TRUE, NULL, &ChildStatus);

  if (EFI_ERROR(Status)) {
    Print(L"Failed to execute binary!\r\n");
    goto END;
  }

  Print(L"Child finished with status: %r\r\n", ChildStatus);


END:

  if (RemoveFileAfterExecution) {
    ShellDeleteFileByName (FilePath);
  }

  if (Command) {
    FreePool (Command);
    Command = NULL;
  }

  return Status;
}


STATIC
EFI_STATUS
EFIAPI
DoLoadFile (
  IN UINT64 FileId
  ) 
{
  EFI_STATUS Status = EFI_SUCCESS;

  if (EFI_ERROR(Status = VesperProtocolSendFetchFileMsg(TcpIo, FileId))) {
    Print(L"Failed to send fetch file msg to remote!\r\n");
    return Status;
  }


  VESPER_PROTOCOL_RESPONSE *Response = NULL;

  if (EFI_ERROR(Status = VesperProtocolRecvResponseAndDealError(TcpIo, &Response))) {
    return Status;
  }

  UINT64 FileSize = Response->Body.MsgLen;
  UINT8 *FileData = Response->Body.Msg;

  DEBUG((DEBUG_INFO, "FileSize: %d\n", FileSize));


  CHAR16 *PathToSaveLoadedBinary = NULL;
  
  if (EFI_ERROR(Status = FindPathToSaveLoadedBinary(&PathToSaveLoadedBinary))) {
    goto END;
  }


  Status = SaveEfiAppBinaryAndExecute(
    FileData, 
    FileSize, 
    PathToSaveLoadedBinary, 
    CliArgs.RemoveBinaryAfterExecution || !CliArgs.SaveBinaryToSet,
    CliArgs.Cli
  );

  if (EFI_ERROR(Status)) {
    goto END;
  }


END:
  if (Response) {
    FreePool (Response);
    Response = NULL;
  }

  if (PathToSaveLoadedBinary) {
    FreePool (PathToSaveLoadedBinary);
    PathToSaveLoadedBinary = NULL;
  }

  return Status;
}



EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;

  AppImageHandle = ImageHandle;
  AppSystemTable = SystemTable;

  if ( EFI_ERROR(Status = ShellInitialize()) ) {
    Print(L"Failed to initialize shell!\r\n");
    return Status;
  }

  UINTN Argc;
  CHAR16 **Argv;

  if ( EFI_ERROR(Status = FindArgcAndArgv(&Argc, &Argv)) ) {
    return Status;
  }


  if ( EFI_ERROR(Status = ParseCli(Argc, Argv)) || CliArgs.ActionUsage ) {
    Usage (Argv[0]);
    return Status;
  }


  if (
    (!CliArgs.IpAddrSet || !CliArgs.PortSet) ||
    (CliArgs.ActionLoadFile && !CliArgs.FileIdSet)
    ) 
  {
    Usage (Argv[0]);
    return EFI_INVALID_PARAMETER;
  }


  if ( EFI_ERROR(Status = PrepareTextIOProtocols()) ) {
    goto END;
  }


  if ( EFI_ERROR(Status = PrepareNetDeviceHandle()) ) {
    Print(L"Failed to prepare net device!\r\n");
    goto END;
  }


  if (EFI_ERROR(Status = CreateSocket(&CliArgs.Ip4Addr, CliArgs.Port, &TcpIo))) {
    DEBUG((DEBUG_ERROR, "Failed to create socket!\n"));
    Print(L"Failed to create socket! Check your network connection and try again.\r\n");
    return Status;
  }


  if (EFI_ERROR(Status = TcpIoConnect(TcpIo, NULL))) {
    DEBUG((DEBUG_ERROR, "Failed on TCP connect!\n"));
    return Status;
  }


  if (CliArgs.ActionListFiles) {
    Status = DoListFiles();
  } else if (CliArgs.ActionLoadFile) {
    Status = DoLoadFile(CliArgs.FileId);
  } else {
    Print(L"No action specified.\r\n");
    Usage(Argv[0]);
    Status = EFI_INVALID_PARAMETER;
  }

  
END:
  CleanUp();

  return Status;
}
