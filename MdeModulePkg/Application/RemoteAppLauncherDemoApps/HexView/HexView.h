/*
    Hex View


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.13 at Jiangchuan, Minhang, Shanghai

    https://gist.github.com/FlowerBlackG/1ed24faf374478bfac470627ce81c5fb

    Modified for Remote App Launcher.
*/

// Original Heading:
/*
 * Portable hexdump util for C/C++
 * 
 * gongty [at] tongji [dot] edu [dot] cn
 * Created on 2024.12.8 at Jiangchuan, Minhang, Shanghai
 * 
 * 
 * Usage:
 *   You can change ReadFunc and WriteFunc to any type you want.
 *   But you should ensure their prototype:
 *   - ReadFunc : Callable. Returning one character as int. EOF for end.
 *   - WriteFunc: Callable. Receive one int as character.
 */

#pragma once

#include <Uefi.h>


typedef VOID (*HexViewWriteFunc) (INT32 Ch, VOID* Data);
typedef INT32 (*HexViewReadFunc) (VOID* Data);


EFIAPI
UINTN
hexView(
  BOOLEAN upperCase,
  HexViewReadFunc in,
  HexViewWriteFunc out,
  VOID *data
  );

