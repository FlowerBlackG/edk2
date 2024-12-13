# App Server Protocol

<center>124033910070 GTY</center>

<center>124033910183 FYT</center>

<center>024033910127 SS</center>

## Conflict Note

If this file conflicts with the Chinese version, you should think the Chinese version is the most reliable.

## Protocol Model

App Server Protocol is a special type of Vesper Control Protocol. You can check the design of [Vesper Control Protocol](https://github.com/FlowerBlackG/vesper/blob/main/doc/vesper-control-protocol.md).

## Header

Every message begins with a header like this:

```
    4B        4B
+---------+---------+
|  magic  |  type   |
+---------+---------+
|       length      |
+-------------------+
```

* magic (uint32): Fixed. ASCII: `KpBL`
* type (uint32): Command identifier. Continue reading to learn more.
* length (uint64): Size of the message without header.

## Protocol Magic

Protocol magic is set to `dDSt`

## Protocol Messages

### 0xA001: Common Response

`Response`

Like the Response in Vesper Control Protocol.

```
  8 Bytes
+-------------------+
|       header      |
+-------------------+
|       header      |
+---------+---------+
|  code   | msg len |
+---------+---------+
|      msg          |
|      ...          |

```

* type (uint32): `0xA001`
* code (uint32): Status code. 0 for OK.
* msg len (uint32): Size of `msg` in Bytes.
* msg (byte array): Data returned.

Response can be used to transfer data. When `code` is not 0, `msg` should be treated as error log. When `code` is 0, `msg`'s meaning differs to their type.

### 0x0101: List Available Files

`ListFiles`

```
    8 Bytes
+----------------+
|     header     |
+----------------+
|     header     |
+----------------+
```

* type (uint32): `0x0101`

---

**Response msg meanings**

Each file's info can be seen as a `(id, name)` pair. Each `id` is an 8-byte integer, `name` is a string. These two follows without gap. A `\0` is followed after each file's info.

Assume we have file **Add.uefi** with `id` 100, the bytes represents it is:

```
00000000  00 00 00 00 00 00 00 64 - 41 64 64 2e 75 65 66 69     .......dAdd.uefi
00000010  00                                                    .
```

Files' info are sticked, distinguished by `\0`.

Assume we have these files in the server:

|     id     |       name       |
| :--------: | :--------------: |
|    0xAB    |     SJTU.efi     |
|    0x92    |   FakeRun.efi   |
|  0x823B5  | unix-v6pp-tj.efi |
| 0x78A9914F | VesperCenter.efi |
| 0x981BAC3 |    OneTJ.efi    |
|  0xABCDEF  |   ZhengQH.efi   |
|    0x46    |   Feng.YT.efi   |
|    0x7F    |   SiPingRd.efi   |
|   0x123   |     1239.efi     |

When query, bytes returned should like this:

```
00000000  00 00 00 00 00 00 00 AB - 53 4A 54 55 2E 65 66 69     ........SJTU.efi
00000010  00 00 00 00 00 00 00 00 - 92 46 61 6B 65 52 75 6E     .........FakeRun
00000020  2E 65 66 69 00 00 00 00 - 00 00 08 23 B5 75 6E 69     .efi.......#.uni
00000030  78 2D 76 36 70 70 2D 74 - 6A 2E 65 66 69 00 00 0C     x-v6pp-tj.efi...
00000040  78 6B 78 A9 91 4F 56 65 - 73 70 65 72 43 65 6E 74     xkx..OVesperCent
00000050  65 72 2E 65 66 69 00 00 - 00 00 00 09 81 BA C3 4F     er.efi.........O
00000060  6E 65 54 4A 2E 65 66 69 - 00 00 00 00 00 00 AB CD     neTJ.efi........
00000070  EF 5A 68 65 6E 67 51 48 - 2E 65 66 69 00 00 00 00     .ZhengQH.efi....
00000080  00 00 00 00 46 46 65 6E - 67 2E 59 54 2E 65 66 69     ....FFeng.YT.efi
00000090  00 00 00 00 00 00 00 00 - 7F 53 69 50 69 6E 67 52     .........SiPingR
000000A0  64 2E 65 66 69 00 00 00 - 00 00 00 00 01 23 31 32     d.efi........#12
000000B0  33 39 2E 65 66 69 00                                  39.efi.
```

### 0x0102: Fetch File Data

`FetchFile`

```
    8 Bytes
+----------------+
|     header     |
+----------------+
|     header     |
+----------------+
|     file id    |
+----------------+
```

* type (uint32): `0x0102`
* file id (uint64)
