/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file aes.cpp
  @brief AES/CMAC helpers
*/
#include "nfc/crypto/aes.hpp"

#include <M5Utility.hpp>
#include <cstring>
#include <mbedtls/aes.h>

namespace m5 {
namespace nfc {
namespace crypto {

namespace {

void left_shift_128(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t next = static_cast<uint8_t>(in[i] << 1);
        out[i]       = static_cast<uint8_t>(next | carry);
        carry        = (in[i] & 0x80) ? 0x01 : 0x00;
    }
}

}  // namespace

bool aes_ecb_encrypt(uint8_t out[16], const uint8_t key[16], const uint8_t in[16])
{
    if (!out || !key || !in) {
        return false;
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
        M5_LIB_LOGE("AES setkey_enc failed");
        std::memset(out, 0, 16);
        mbedtls_aes_free(&aes);
        return false;
    }
    if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out) != 0) {
        M5_LIB_LOGE("AES crypt_ecb failed");
        std::memset(out, 0, 16);
        mbedtls_aes_free(&aes);
        return false;
    }
    mbedtls_aes_free(&aes);
    return true;
}

bool aes_cbc_crypt(uint8_t* out, const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* in, const size_t len,
                   const bool encrypt)
{
    if (!out || !key || !iv_in || (!in && len)) {
        return false;
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (encrypt) {
        if (mbedtls_aes_setkey_enc(&aes, key, 128) != 0) {
            M5_LIB_LOGE("AES setkey_enc failed");
            std::memset(out, 0, len);
            mbedtls_aes_free(&aes);
            return false;
        }
    } else {
        if (mbedtls_aes_setkey_dec(&aes, key, 128) != 0) {
            M5_LIB_LOGE("AES setkey_dec failed");
            std::memset(out, 0, len);
            mbedtls_aes_free(&aes);
            return false;
        }
    }
    uint8_t iv[16]{};
    std::memcpy(iv, iv_in, sizeof(iv));
    if (mbedtls_aes_crypt_cbc(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv, in, out) != 0) {
        M5_LIB_LOGE("AES crypt_cbc failed");
        std::memset(out, 0, len);
        mbedtls_aes_free(&aes);
        return false;
    }
    mbedtls_aes_free(&aes);
    return true;
}

bool cmac_subkeys(uint8_t k1[16], uint8_t k2[16], const uint8_t key[16])
{
    if (!k1 || !k2 || !key) {
        return false;
    }
    static constexpr uint8_t desfire_rb = 0x87;
    uint8_t l[16]{};
    uint8_t zero[16]{};
    if (!aes_ecb_encrypt(l, key, zero)) {
        return false;
    }
    left_shift_128(l, k1);
    if (l[0] & 0x80) {
        k1[15] ^= desfire_rb;
    }
    left_shift_128(k1, k2);
    if (k1[0] & 0x80) {
        k2[15] ^= desfire_rb;
    }
    return true;
}

bool cmac_aes_128(uint8_t out[16], const uint8_t key[16], const uint8_t* msg, const size_t msg_len)
{
    if (!out || !key || (!msg && msg_len)) {
        return false;
    }
    uint8_t k1[16]{};
    uint8_t k2[16]{};
    if (!cmac_subkeys(k1, k2, key)) {
        return false;
    }

    const size_t n           = (msg_len + 15) / 16;
    const bool last_complete = (msg_len != 0) && (msg_len % 16 == 0);

    uint8_t last_block[16]{};
    if (n == 0) {
        last_block[0] = 0x80;
        for (int i = 0; i < 16; ++i) {
            last_block[i] ^= k2[i];
        }
    } else {
        const uint8_t* last = msg + (n - 1) * 16;
        if (last_complete) {
            std::memcpy(last_block, last, 16);
            for (int i = 0; i < 16; ++i) {
                last_block[i] ^= k1[i];
            }
        } else {
            const size_t rem = msg_len - (n - 1) * 16;
            std::memcpy(last_block, last, rem);
            last_block[rem] = 0x80;
            for (int i = 0; i < 16; ++i) {
                last_block[i] ^= k2[i];
            }
        }
    }

    uint8_t x[16]{};
    uint8_t y[16]{};
    for (size_t i = 0; i + 1 < n; ++i) {
        for (int j = 0; j < 16; ++j) {
            y[j] = static_cast<uint8_t>(x[j] ^ msg[i * 16 + j]);
        }
        if (!aes_ecb_encrypt(x, key, y)) {
            return false;
        }
    }
    for (int j = 0; j < 16; ++j) {
        y[j] = static_cast<uint8_t>(x[j] ^ last_block[j]);
    }
    return aes_ecb_encrypt(out, key, y);
}

}  // namespace crypto
}  // namespace nfc
}  // namespace m5
