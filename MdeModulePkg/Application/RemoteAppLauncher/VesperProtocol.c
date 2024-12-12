/*
    Remote App Launcher :: Vesper Protocol


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.12 at Jiangchuan, Minhang, Shanghai

    Reference:
      https://github.com/FlowerBlackG/vesper/blob/main/doc/vesper-control-protocol.md

*/


#include <Library/DebugLib.h>
#include "./VesperProtocol.h"


STATIC CONST CHAR8* VESPER_PROTOCOL_MAGIC_STR = "dDSt";


/**
 * 
 * 
 * @param Type In host's byte order.
 * @param Length In host's byte order.
 * @param Header Values' byte order is net's (big endian).
 */
STATIC
VOID
MakeHeader (
  IN UINT32 Type,
  IN UINT64 Length,
  OUT VESPER_PROTOCOL_HEADER *Header
  ) 
{
  CopyMem ((VOID*) Header->Magic, (VOID*) VESPER_PROTOCOL_MAGIC_STR, 4);
  Header->Type = htonl(Type);
  Header->Length = htonq(Length);
}


/**
 * The caller is responsible for freeing NetBuf (by calling NetbufFree).
 */
STATIC
EFI_STATUS
EFIAPI
AllocNetBufWithSpace (
  IN UINT32 Len,
  OUT NET_BUF **NetBuf,
  OUT UINT8 **Data
  ) 
{
  NET_BUF *Buf = NetbufAlloc(Len);

  if (!Buf)
    return EFI_OUT_OF_RESOURCES;

  *NetBuf = Buf;
  *Data = NetbufAllocSpace (Buf, Len, NET_BUF_TAIL);

  return EFI_SUCCESS;
}


EFI_STATUS
EFIAPI
VesperProtocolSend (
  IN TCP_IO *TcpIo,
  IN UINT32 Type,
  IN UINT64 DataLen,
  IN UINT8* Data OPTIONAL
  )
{
  if (DataLen && !Data)
    return EFI_INVALID_PARAMETER;

  EFI_STATUS Status = EFI_SUCCESS;


  VESPER_PROTOCOL_HEADER Header;
  MakeHeader(Type, 0, &Header);

  UINT32 HeaderSize = sizeof(Header);
  UINT64 MsgSize = HeaderSize + DataLen;


  // Vesper Protocol supports messages larger than 4G, but edk2 doesn't support
  // that large packet natively.
  //
  // I don't want to implement 4G+ msg support under edk2 now, as this app won't
  // require this feature.
  if (MsgSize > __UINT32_MAX__)
    return EFI_PROTOCOL_ERROR;  

  // Now, we can say the value of (UINT32) MsgSize equals to (UINT64) MsgSize.


  NET_BUF *NetBuf;
  UINT8 *BufData;

  if (EFI_ERROR(Status = AllocNetBufWithSpace((UINT32) MsgSize, &NetBuf, &BufData))) {
    DEBUG((DEBUG_ERROR, "Failed to alloc netbuf with space! %r\n", Status));
    return Status;
  }


  CopyMem ((VOID*) BufData, (VOID*) &Header, HeaderSize);
  CopyMem ((VOID*) (BufData + HeaderSize), (VOID*) Data, DataLen);
  
  if (EFI_ERROR(Status = TcpIoTransmit(TcpIo, NetBuf))) {
    DEBUG((DEBUG_ERROR, "Failed to send Vesper Protocol msg! %r\n", Status));
    goto END;
  }


END:

  NetbufFree(NetBuf);
  return Status;
}


EFI_STATUS
EFIAPI
VesperProtocolSendListFilesMsg (
  IN TCP_IO *TcpIo
  ) 
{
  return VesperProtocolSend (
    TcpIo,
    VESPER_PROTOCOL_TYPE_LIST_FILES,
    0, 
    NULL
  );
}



EFI_STATUS
EFIAPI
VesperProtocolSendFetchFileMsg (
  IN TCP_IO *TcpIo
  )  
{
  return VesperProtocolSend (
    TcpIo,
    VESPER_PROTOCOL_TYPE_FETCH_FILE,
    0, 
    NULL
  );
}


EFI_STATUS
EFIAPI
VesperProtocolRecvHeader (
  IN TCP_IO *TcpIo,
  OUT VESPER_PROTOCOL_HEADER *Header
  ) 
{
  if (!Header)
    return EFI_INVALID_PARAMETER;

  EFI_STATUS Status = EFI_SUCCESS;

  UINT32 HeaderSize = sizeof(VESPER_PROTOCOL_HEADER);

  NET_BUF *NetBuf;
  UINT8 *Data;

  if (EFI_ERROR(Status = AllocNetBufWithSpace(HeaderSize, &NetBuf, &Data))) {
    DEBUG((DEBUG_ERROR, "Failed to alloc netbuf with space!\n"));
    return Status;
  }


  if (EFI_ERROR(Status = TcpIoReceive(TcpIo, NetBuf, FALSE, NULL))) {
    DEBUG((DEBUG_ERROR, "Failed receive Vesper Protocol header! %r\n", Status));
    goto END;
  }


  // Check Magic.

  if ( *(CONST INT32*) VESPER_PROTOCOL_MAGIC_STR != *(CONST INT32*) Data ) {
    DEBUG((DEBUG_ERROR, "Bad Magic!\n"));
    Status = EFI_PROTOCOL_ERROR;
    goto END;
  }


  // Copy Header.

  CopyMem ((VOID *) Header, (VOID *) Data, HeaderSize);


  // Convert values' byte order to native.

  Header->Type = ntohl(Header->Type);
  Header->Length = ntohq(Header->Length);


END:
  NetbufFree(NetBuf);
  return Status;
}



EFI_STATUS
EFIAPI
VesperProtocolRecv (
  IN TCP_IO *TcpIo,
  OUT VESPER_PROTOCOL_MSG **Msg
  )
{
  if (!Msg)
    return EFI_INVALID_PARAMETER;

  EFI_STATUS Status = EFI_SUCCESS;

  VESPER_PROTOCOL_HEADER Header;

  if (EFI_ERROR(Status = VesperProtocolRecvHeader(TcpIo, &Header))) {
    DEBUG((DEBUG_ERROR, "Failed to recv Vesper Protocol header!\n"));
    return Status;
  }

  if (Header.Length > __UINT32_MAX__)
    return EFI_PROTOCOL_ERROR;

  // TODO

END:

  return Status;
}
