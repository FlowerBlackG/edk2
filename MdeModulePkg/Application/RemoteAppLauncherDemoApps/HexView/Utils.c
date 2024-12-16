/*
    Remote App Launcher :: Utils


    gongty [at] tongji [dot] edu [dot] cn

    Created on 2024.12.12 at Jiangchuan, Minhang, Shanghai

*/


#include "./Utils.h"



INT32 atoi(CONST CHAR8* str) {
    if (!str)
        return 0;

    INT32 ret = 0;
    INT32 sign = 1;

    INT32 pos = 0;
    
    while ((str[pos] == ' ' || str[pos] == '\t') && str[pos] != '\0') {
        pos++;
    }

    if (str[pos] == '+')
        pos++;
    else if (str[pos] == '-') {
        sign = -1;
        pos++;
    }

    while (str[pos] >= '0' && str[pos] <= '9') {
        ret *= 10;
        ret += str[pos] - '0';
        pos++;
    }

    return (INT32) (ret * sign);
}


INT32 char16_to_int(CONST CHAR16* str) {
    if (!str)
        return 0;

    INT32 ret = 0;
    INT32 sign = 1;

    INT32 pos = 0;
    
    while ((str[pos] == ' ' || str[pos] == '\t') && str[pos] != '\0') {
        pos++;
    }

    if (str[pos] == '+')
        pos++;
    else if (str[pos] == '-') {
        sign = -1;
        pos++;
    }

    while (str[pos] >= '0' && str[pos] <= '9') {
        ret *= 10;
        ret += str[pos] - '0';
        pos++;
    }

    return (INT32) (ret * sign);
}
