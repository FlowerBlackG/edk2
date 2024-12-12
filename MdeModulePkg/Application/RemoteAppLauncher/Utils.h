/*
    Remote App Launcher :: Utils


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.12 at Jiangchuan, Minhang, Shanghai

*/

#pragma once

#include <Uefi.h>


/**
 * 
 * 
 * @param str 
 * @bug UB when number in str is too long.
 */
INT32 atoi(CONST CHAR8* str);


/**
 * 
 * 
 * @param str 
 * @bug UB when number in str is too long.
 */
INT32 char16_to_int(CONST CHAR16* str);



/*

    adl/endian.h from Amkos by SJTU-DDST

*/

#ifndef __BYTE_ORDER__
    #error "__BYTE_ORDER__ undefined. Compiler you are using is not supported by us."
#endif

#ifndef BYTE_ORDER
    #define BYTE_ORDER __BYTE_ORDER__
#endif

#ifndef BIG_ENDIAN
    #define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#ifndef LITTLE_ENDIAN
    #define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif

#if ((BYTE_ORDER != BIG_ENDIAN) && (BYTE_ORDER != LITTLE_ENDIAN))
    #error "Strange system. Our system won't work on your device."
#endif


inline UINT16 be16toh(UINT16 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return x;
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return __builtin_bswap16(x);
#endif
}


inline UINT32 be32toh(UINT32 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return x;
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return __builtin_bswap32(x);
#endif

}


inline UINT64 be64toh(UINT64 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return x;
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return __builtin_bswap64(x);
#endif

}



inline UINT16 htobe16(UINT16 x) {
    return be16toh(x);
}
inline UINT32 htobe32(UINT32 x) {
    return be32toh(x);
}
inline UINT64 htobe64(UINT64 x) {
    return be64toh(x);
}



inline UINT16 htole16(UINT16 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return __builtin_bswap16(x);
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return x;
#endif

}


inline UINT32 htole32(UINT32 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return __builtin_bswap32(x);
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return x;
#endif
}


inline UINT64 htole64(UINT64 x) {
#if BYTE_ORDER == BIG_ENDIAN
    return __builtin_bswap64(x);
#else  // BYTE_ORDER == LITTLE_ENDIAN
    return x;
#endif
}


inline UINT16 le16toh(UINT16 x) {
    return htole16(x);
}

inline UINT32 le32toh(UINT32 x) {
    return htole32(x);
}

inline UINT64 le64toh(UINT64 x) {
    return htole64(x);
}


/*

    adl/arpa/inet.h from Amkos by SJTU-DDST

*/



inline UINT32 htonl(UINT32 x) {
    return htobe32(x);
}


inline UINT16 htons(UINT16 x) {
    return htobe16(x);
}


inline UINT64 htonq(UINT64 x) {
    return htobe64(x);
}


inline UINT32 ntohl(UINT32 x) {
    return htonl(x);
}

inline UINT16 ntohs(UINT16 x) {
    return htons(x);
}

inline UINT64 ntohq(UINT64 x) {
    return htonq(x);
}



/*

    adl/sys/types.h from Amkos by SJTU-DDST

*/


#ifndef __packed
    #define __packed __attribute__((packed))
#endif
