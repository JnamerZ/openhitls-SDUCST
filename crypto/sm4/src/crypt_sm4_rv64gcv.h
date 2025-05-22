#ifndef CRYPT_SM4_RV64GCV_H
#define CRYPT_SM4_RV64GCV_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>

void Vxor_SM4_CBC_Encrypt(const uint8_t *in, uint8_t *out, const uint32_t len, const uint32_t *key, uint8_t *iv);
void Vxor_SM4_CBC_Decrypt(const uint8_t *in, uint8_t *out, const uint32_t len, const uint32_t *key, uint8_t *iv);
void Vxor_SM4_CBC_Decrypt_FirstBlock(const uint8_t *in, uint8_t *out, const uint32_t *key, uint8_t *iv);

#endif
#endif

