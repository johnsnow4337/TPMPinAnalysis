#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sha256.h"

#define HASHITERS 0x100000

//"BitLockerAuthData\x00\x00\x00"
const char CONCATSTR[]  = { 0x42, 0x69, 0x74, 0x4c, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x41, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00 };

#define LOGLEVEL 0

struct hashIterStruct {
    BYTE updateHash[32];
    BYTE inputHash[32];
    BYTE salt[16];
    unsigned long long hashCount;
};


void printHex(BYTE*input, int size){
    for (int i = 0; i <size;i++){
        printf("%02x ", input[i]);
    }
    printf("\n");
}

int stretchKey(BYTE* inputHash, const BYTE* salt, BYTE* outHash){
    struct hashIterStruct pinHashStruct;
    memcpy(pinHashStruct.inputHash,inputHash,32*sizeof(BYTE));
    memcpy(pinHashStruct.salt,salt,16*sizeof(BYTE));
    memset(pinHashStruct.updateHash,0,32*sizeof(BYTE));
    pinHashStruct.hashCount = 0;

    #if (LOGLEVEL > 0)
        printf("updateHash: \t");
        printHex(pinHashStruct.updateHash,0x20);
        printf("inputHash: \t");
        printHex(pinHashStruct.inputHash,0x20);
        printf("salt: \t\t");
        printHex(pinHashStruct.salt,0x10);
        printf("hashCount: \t");
        printHex(&(pinHashStruct.hashCount),8);
    #endif
    SHA256_CTX stretchCtx;
    

    for (int i = 0; i < HASHITERS; i++){
        pinHashStruct.hashCount = i;
        sha256_init(&stretchCtx);
        sha256_update(&stretchCtx,&pinHashStruct, sizeof(struct hashIterStruct));
	    sha256_final(&stretchCtx, pinHashStruct.updateHash);
    }

    BYTE concatBuf[0x34];
    memcpy(concatBuf, pinHashStruct.updateHash, 0x20);
    memcpy(concatBuf+0x20, CONCATSTR, 0x14);
    #if (LOGLEVEL > 0)
        printf("Stretched Hash: ");
        printHex(concatBuf,0x20);
    #endif
    BYTE finalHash[0x20];

    SHA256_CTX concatCtx;
    sha256_init(&concatCtx);
    sha256_update(&concatCtx,concatBuf,0x34);
    sha256_final(&concatCtx,finalHash);

    #if (LOGLEVEL > 0)
        printf("Concatonated Hash: ");
        printHex(finalHash,0x20);
    #endif

    SHA256_CTX shortCtx;
    sha256_init(&shortCtx);
    sha256_update(&shortCtx,finalHash,0x20);
    sha256_final(&shortCtx,outHash);

    return 1;
}

BYTE* utf16Convert(char* pin, int *unicodeLen){
    int pinlen;
    pinlen = strlen(pin);
    if (pin[pinlen-1] == 0xa){
        pinlen = pinlen - 1;
    }
    BYTE* unicodePin = malloc(pinlen*2);
    for (int i = 0; i < pinlen; i++){
        unicodePin[i*2] = pin[i];
        unicodePin[i*2+1] = 0;
    }
    *unicodeLen = pinlen*2;
    return unicodePin;
}

int computeHash(char* testPin){
    int unicodeLen;
    BYTE* unicodePin = utf16Convert(testPin, &unicodeLen);
    
    BYTE firstHash[0x20];
    SHA256_CTX initCtx;
    sha256_init(&initCtx);
    sha256_update(&initCtx,unicodePin,unicodeLen);
    sha256_final(&initCtx,&firstHash);

    BYTE secondHash[0x20];
    SHA256_CTX secondInitCtx;
    sha256_init(&secondInitCtx);
    sha256_update(&secondInitCtx,firstHash,0x20);
    sha256_final(&secondInitCtx,secondHash);

    BYTE stretchedHash[0x20];
    const BYTE salt[] = {0xf9, 0x33, 0x9f, 0xae, 0xb3, 0xcc, 0xb8, 0xa2, 0x11, 0x55, 0x38, 0x9b, 0xf0, 0xbd, 0x75, 0x81 };
    stretchKey(secondHash, salt, stretchedHash);
    if (stretchedHash[0] == 0xad){
        printf("Final Hash (%s): ", testPin);
        printHex(stretchedHash,0x14);
    }

    return 1;
}
void addNumberToStringInt(char *str, int add, char *result, int width) {
    // Convert string to integer
    int num = atoi(str);

    // Add the number
    num += add;

    // Convert back to string with leading zeros
    sprintf(result, "%0*d", width, num);
}
int main(){
    char pin[20] = "87654320";
    int pinnum = atoi(pin);
    int width = strlen(pin);
/*     printf("Enter pin:");
    fgets (pin, 20, stdin); */
    char result[20];
    for (int i; i<10; i++){
        pinnum+= i;
        sprintf(result, "%0*d",width,pinnum);
        computeHash(result);
    }
    printf("%s",result);
    return 1;
}
/*const uint8_t data[32] = {
    0xAD, 0x32, 0x92, 0x64, 0x27, 0x2D, 0x4C, 0x8C, 0xA3, 0xD9, 0x4A, 0xCA, 0x7B, 0xF0, 0x66, 0x94, 
    0x60, 0x94, 0x95, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
};*/
