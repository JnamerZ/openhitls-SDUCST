/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "crypt_eal_cipher.h" // Header file of the interfaces for symmetric encryption and decryption.
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_algid.h" // Algorithm ID list.
#include "crypt_errno.h" // Error code list.

#define KEYLEN 16
#define IVLEN 16
#define ROUNDS 100

void *StdMalloc(uint32_t len) {
    return malloc((size_t)len);
}

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line); // Obtain the name and number of lines of the error file.
    printf("failed at file %s at line %d\n", file, line);
}

int32_t init_ctx(CRYPT_EAL_CipherCtx **ctx_ptr, bool is_encrypt, uint8_t *key, uint8_t *iv) {
    int32_t ret = -1;
    CRYPT_EAL_CipherCtx *ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (ctx == NULL) {
        PrintLastError();
        BSL_ERR_DeInit();
        goto INITRET;
    }
    ret = CRYPT_EAL_CipherInit(ctx, key, KEYLEN, iv, IVLEN, is_encrypt);
    if (ret != CRYPT_SUCCESS) {
        // Output the error code. You can find the error information in **crypt_errno.h** based on the error code.
        printf("error at enc CRYPT_EAL_CipherInit\nerror code is %x\n", ret);
        PrintLastError();
        goto INITRET;
    }
    // Set the padding mode.
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        printf("error at enc CRYPT_EAL_CipherSetPadding\nerror code is %x\n", ret);
        PrintLastError();
        goto INITRET;
    }
    *ctx_ptr = ctx;
    ret = 0;

INITRET:
    return ret;
}

void free_ctx(CRYPT_EAL_CipherCtx *ctx) {
    CRYPT_EAL_CipherFreeCtx(ctx);
}

int32_t encrypt(CRYPT_EAL_CipherCtx *ctx,
                uint8_t *data, size_t dataLen, uint8_t *cipherText, size_t ctLen,
                uint32_t *outLen, uint32_t *outTotalLen) {
    int32_t ret;
    
    ret = CRYPT_EAL_CipherUpdate(ctx, data, dataLen, cipherText, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error at enc CRYPT_EAL_CipherUpdate\nerror code is %x\n", ret);
        PrintLastError();
        goto ENCRET;
    }

    *outTotalLen += *outLen;
    *outLen = ctLen - *outTotalLen;

    ret = CRYPT_EAL_CipherFinal(ctx, cipherText + *outTotalLen, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error at enc CRYPT_EAL_CipherFinal\nerror code is %x\n", ret);
        PrintLastError();
        goto ENCRET;
    }

    *outTotalLen += *outLen;
ENCRET:
    return ret;
}

int32_t decrypt(CRYPT_EAL_CipherCtx *ctx,
                uint8_t *plainText, size_t ptLen, uint8_t *cipherText, size_t ctLen,
                uint32_t *outLen, uint32_t *outTotalLen) {
    int32_t ret;
    // Enter the ciphertext data.
    ret = CRYPT_EAL_CipherUpdate(ctx, cipherText, ctLen, plainText, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error at dec CRYPT_EAL_CipherUpdate\nerror code is %x\n", ret);
        PrintLastError();
        goto DECRET;
    }
    *outTotalLen += *outLen;
    *outLen = ptLen - *outTotalLen;

    // Decrypt the last segment of data and remove the filled content.
    ret = CRYPT_EAL_CipherFinal(ctx, plainText + *outTotalLen, outLen);
    if (ret != CRYPT_SUCCESS) {
        printf("error at dec CRYPT_EAL_CipherFinal\nerror code is %x\n", ret);
        PrintLastError();
        goto DECRET;
    }

    *outTotalLen += *outLen;
DECRET:
    return ret;
}

#define BUFFER_SIZE 268435456

int main(void)
{
    uint8_t iv[16] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,   // 0x0123456789abcdef
                      0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xad, 0x0b};  // 0x0badcofedeadbeef
    //  iv hex: efcdab8967452301efbeaddefecaad0b
    uint8_t key[16] = {0xee, 0xff, 0xc0, 0x1e, 0xbb, 0xba, 0xaf, 0x1e,  // 0x1eafbabb1ec0ffee
                       0x1e, 0xab, 0x11, 0xca, 0x1e, 0xbb, 0xba, 0xff}; // 0xffbabb1eca11ab1e
    // key hex: eeffc01ebbbaaf1e1eab11ca1ebbbaff
    uint8_t *cipherText, *plainText, *data, *ans;
    uint32_t dataLen, ansLen, outTotalLen, outLen, cipherTextLen;
    int32_t ret, ipt, ans_file;
    struct timespec start, end; register double delta;
    struct stat fs;
    
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    //% dd if=/dev/urandom of=./input_file bs=x count=y status=progress
    ipt = open("/home/orangepi/input_file",  O_RDONLY);
    //% openssl enc -sm4-cbc -in ./input_file -out ./output_file.answer \
    //  -K eeffc01ebbbaaf1e1eab11ca1ebbbaff \
    // -iv efcdab8967452301efbeaddefecaad0b
    ans_file = open("/home/orangepi/output_file.answer", O_RDONLY);

    if (ipt < 0 || ans_file < 0) {
        perror("open");
        goto EXIT;
    }
    
    if(fstat(ipt, &fs) == -1) {
        perror("fstat");
        goto EXIT;
    }

    dataLen = fs.st_size;
    data = mmap(NULL, dataLen, PROT_READ, MAP_SHARED, ipt, 0);
    close(ipt);

    if(fstat(ans_file, &fs) == -1) {
        perror("fstat");
        goto EXIT;
    }

    ansLen = fs.st_size;
    ans = mmap(NULL, ansLen, PROT_READ, MAP_SHARED, ans_file, 0);
    close(ans_file);

    cipherText = mmap(NULL, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
    plainText  = mmap(NULL, BUFFER_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);

    if ((size_t)data == -1 || (size_t)ans == -1 || (size_t)cipherText == -1 || (size_t)plainText == -1) {
        perror("mmap");
        goto EXIT;
    }

    printf("plain text length: %d\n", dataLen);

    BSL_ERR_Init();

    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);

    CRYPT_EAL_CipherCtx *ctx;

    delta = 0;
    puts("Testing encrypt...");
    for (int round = 0; round < ROUNDS; round++) {
        ret = init_ctx(&ctx, true, key, iv);
        if (ret) {
            printf("init ctx error\nerror code: %x\n", ret);
            goto EXIT;
        }
        outTotalLen = 0;
        outLen = BUFFER_SIZE;
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = encrypt(ctx, data, dataLen, cipherText, sizeof(cipherText), &outLen, &outTotalLen);
        clock_gettime(CLOCK_MONOTONIC, &end);
        delta += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
        free_ctx(ctx);
    }
    
    printf("cipher text length: %d\n", outTotalLen);
    
    if (outTotalLen != ansLen || memcmp(cipherText, ans, ansLen) != 0) {
        printf("ciphertext comparison failed\n");
        putchar('\n');
        goto EXIT;
    }
    printf("encrypt time usage per round: %.2fms\n", delta / ROUNDS);

    delta = 0;
    cipherTextLen = outTotalLen;
    puts("Testing decrypt...");
    for (int round = 0; round < ROUNDS; round++) {
        ret = init_ctx(&ctx, false, key, iv);
        if (ret) {
            printf("init ctx error\nerror code: %x\n", ret);
            goto EXIT;
        }
        outTotalLen = 0;
        outLen = BUFFER_SIZE;
        clock_gettime(CLOCK_MONOTONIC, &start);
        ret = decrypt(ctx, plainText, sizeof(plainText), cipherText, cipherTextLen, &outLen, &outTotalLen);
        clock_gettime(CLOCK_MONOTONIC, &end);
        delta += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
        if (ret != CRYPT_SUCCESS) {
            goto EXIT;
        }
        free_ctx(ctx);
    }
    

    printf("decrypted plaintext length: %d\n", outTotalLen);
    printf("decrypt time usage per round: %.2fms\n", delta / ROUNDS);

    if (outTotalLen != dataLen || memcmp(plainText, data, dataLen) != 0) {
        printf("plaintext comparison failed\n");
        goto EXIT;
    }
    printf("pass \n");

EXIT:
    BSL_ERR_DeInit();
    return ret;
}