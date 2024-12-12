/*
    Remote App Launcher :: Vesper Protocol


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.12 at Jiangchuan, Minhang, Shanghai

    Reference:
      https://github.com/FlowerBlackG/vesper/blob/main/doc/vesper-control-protocol.md

*/


#pragma once


#include "./Utils.h"

#include <Library/TcpIoLib.h>


/**
 * Values' byte order is specified by the specific using scenario.
 */
typedef struct {
    UINT8 Magic[4];
    UINT32 Type; 
    UINT64 Length;
} __packed VESPER_PROTOCOL_HEADER;


typedef struct {
  VESPER_PROTOCOL_HEADER Header;
  UINT8 Data[0];
} __packed VESPER_PROTOCOL_MSG;


#define VESPER_PROTOCOL_TYPE_RESPONSE 0xA001
#define VESPER_PROTOCOL_TYPE_LIST_FILES 0x0101
#define VESPER_PROTOCOL_TYPE_FETCH_FILE 0x0102


typedef struct {
    UINT32 Code;
    UINT32 MsgLen;
    UINT8 Msg[0];
} __packed VESPER_PROTOCOL_RESPONSE_BODY;


typedef struct {
  VESPER_PROTOCOL_HEADER Header;
  VESPER_PROTOCOL_RESPONSE_BODY Body;
} __packed VESPER_PROTOCOL_RESPONSE;


EFI_STATUS
EFIAPI
VesperProtocolSend (
  IN TCP_IO *TcpIo,
  IN UINT32 Type,
  IN UINT64 DataLen,
  IN UINT8* Data OPTIONAL
  );


EFI_STATUS
EFIAPI
VesperProtocolSendListFilesMsg (
  IN TCP_IO *TcpIo
  );



EFI_STATUS
EFIAPI
VesperProtocolSendFetchFileMsg (
  IN TCP_IO *TcpIo
  );


EFI_STATUS
EFIAPI
VesperProtocolRecvHeader (
  IN TCP_IO *TcpIo,
  OUT VESPER_PROTOCOL_HEADER *Header
  );


EFI_STATUS
EFIAPI
VesperProtocolRecv (
  IN TCP_IO *TcpIo,
  OUT VESPER_PROTOCOL_MSG **Msg
  );

