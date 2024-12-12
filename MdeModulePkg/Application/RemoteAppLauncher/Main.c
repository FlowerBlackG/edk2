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


STATIC EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *TextOut = NULL;
STATIC EFI_SIMPLE_TEXT_INPUT_PROTOCOL *TextIn = NULL;

STATIC EFI_HANDLE NetDeviceHandle = NULL;

STATIC EFI_TCP4_CONFIG_DATA Tcp4ConfigData;


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
) {

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


EFI_STATUS TODO_TRY_TcpIO() {
  EFI_STATUS Status;

  TCP_IO_CONFIG_DATA confData;
  ZeroMem (&confData, sizeof(TCP_IO_CONFIG_DATA));
  
  
  EFI_IPv4_ADDRESS addr;
  addr.Addr[0] = 202;
  addr.Addr[1] = 120;
  addr.Addr[2] = 37;
  addr.Addr[3] = 25;

  BuildTcp4ConfigData(&Tcp4ConfigData,
    &addr,
    20024
  );


  TCP_IO tcpio;
  NET_BUF *nbuf;

  Status = TcpIoCreateSocket(
    gImageHandle, NetDeviceHandle,
    TCP_VERSION_4, &confData, &tcpio
  );

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Failed to create socket io! %r \n", Status));
    return Status;
  }

  DEBUG((DEBUG_INFO, "Socket created. \n"));


  EFI_TCP4_PROTOCOL* Tcp4 = tcpio.Tcp.Tcp4;

  Tcp4->Configure(Tcp4, NULL); // Reset before configure.



  Status = Tcp4->Configure(Tcp4, &Tcp4ConfigData);

  if (EFI_ERROR(Status)) {

    DEBUG((DEBUG_ERROR, "Reconfig Tcp4 data failed. %r\n", Status));

  }



    Status = TcpIoConnect(&tcpio, NULL);



  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "failed on connect %r \n", Status));
    return Status;
  }

       DEBUG((DEBUG_ERROR, "Connected !!!!!!!!\n"));
       CONST int BUF_SIZE = TODO_TestVal;
    nbuf = NetbufAlloc (BUF_SIZE);
    if (!nbuf) {
       DEBUG((DEBUG_ERROR, "failed on alloc nbuf\n"));
      return EFI_ABORTED;
    }

  UINT8 *packet = NetbufAllocSpace(nbuf, BUF_SIZE, NET_BUF_TAIL);

  if (!packet) {

    return EFI_OUT_OF_RESOURCES;
  }

    DEBUG((DEBUG_INFO, "Ready to receive!\n"));
  Status = TcpIoReceive(&tcpio, nbuf, FALSE, NULL);

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "Error on TCP Recv: %r \n", Status));
    return Status;
  }


  DEBUG((DEBUG_ERROR, "Received !!!!!!!!\n"));

  DEBUG((DEBUG_INFO, "nbuf size: %d\n", nbuf->TotalSize));
  
  
  packet[24] = '\0';
  DEBUG((DEBUG_INFO, (char*)packet));
  

return EFI_SUCCESS;
}


STATIC
VOID
EFIAPI
CleanUp()
{

}



EFI_STATUS
EFIAPI
ShellAppMain (
  IN UINTN     Argc,
  IN CHAR16  **Argv
  )
{
  EFI_STATUS Status;

  // TODO: Check parameters.


  if ( EFI_ERROR(Status = PrepareTextIOProtocols()) ) {
    goto END;
  }

  if ( EFI_ERROR(Status = PrepareNetDeviceHandle()) ) {
    goto END;
  }
  



  Status = TODO_TRY_TcpIO();

  
END:
  CleanUp();

  return Status;
}
