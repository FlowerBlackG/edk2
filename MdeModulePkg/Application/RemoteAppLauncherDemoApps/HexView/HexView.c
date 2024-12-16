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


#include "./HexView.h"


#ifndef EOF
  #define EOF (-1)
#endif


typedef HexViewReadFunc ReadFunc;
typedef HexViewWriteFunc WriteFunc;


/**
 * @param num
 * @param width Pass 0 for non-fixed width.
 *              If num's hex width is wider, this argument is ignored.
 * @param upperCase Pass non-zero for upper-case. Pass zero for lower-case.
 */
STATIC
VOID
EFIAPI
writeHex(
  UINTN num,
  INT32 width,
  BOOLEAN upperCase,
  WriteFunc out,
  VOID *data
  )
{
  INT32 digitWidth = 1;

  {
    UINTN needle = 0xF;
    while (needle < num)
    {
      needle <<= 4;
      needle |= 0xF;
      digitWidth++;
    }

    if (width > 0)
    {
      for (int w = digitWidth; w < width; w++)
        out('0', data);
    }
  }

  while (digitWidth)
  {
    unsigned long digit = num >> ((digitWidth - 1) * 4);
    digit &= 0xF;
    if (digit >= 0 && digit <= 9)
    {
      out(digit + '0', data);
    }
    else
    { // digit is in [a, f]
      out(digit - 0xA + (upperCase ? 'A' : 'a'), data);
    }

    digitWidth--;
  }
}


STATIC
VOID
EFIAPI
writeLine(
  UINTN addr,
  INT32 buf[],
  UINTN len,
  BOOLEAN upperCase,
  WriteFunc out,
  VOID *data
  )
{
  writeHex(addr, 8, upperCase, out, data);
  out(' ', data);
  out(' ', data);

  for (int i = 0; i < 16; i++)
  {
    if (i == 8)
    {
      out(i < len ? '-' : ' ', data);
      out(' ', data);
    }
    if (i < len)
    {

      writeHex(buf[i] & 0xFF, 2, upperCase, out, data);
    }
    else
    {
      out(' ', data);
      out(' ', data);
    }
    out(' ', data);
  }

  out(' ', data);
  out(' ', data);
  out(' ', data);
  out(' ', data);
  for (int i = 0; i < len; i++)
  {
    if (buf[i] >= 33 && buf[i] <= 126)
      out(buf[i], data);
    else
      out('.', data);
  }

  out('\n', data);
}


EFIAPI
UINTN
hexView(
  BOOLEAN upperCase,
  ReadFunc in,
  WriteFunc out,
  VOID *data
  )
{
  INT32 buf[16];
  INT32 pos = 0; // One after last occupied.

  UINTN addr = 0;
  UINTN bytesRead = 0;

  while (TRUE)
  {
    INT32 ch = in(data);
    if (ch == EOF)
      break;

    buf[pos++] = ch;
    if (pos == 16)
    {
      writeLine(addr, buf, 16, upperCase, out, data);
      addr += 16;
      pos = 0;
    }
  }

  if (pos)
    writeLine(addr, buf, pos, upperCase, out, data);

  return bytesRead;
}
