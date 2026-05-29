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
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR >= 4
#include <psa/crypto.h>
#include <vector>
#else
#include <mbedtls/aes.h>
#endif

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

#if MBEDTLS_VERSION_MAJOR >= 4
bool psa_import_aes_key(psa_key_id_t& key_id, const uint8_t key[16], const psa_algorithm_t alg,
                        const psa_key_usage_t usage)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        M5_LIB_LOGE("PSA crypto init failed");
        return false;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_usage_flags(&attributes, usage);

    const psa_status_t status = psa_import_key(&attributes, key, 16, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) {
        M5_LIB_LOGE("PSA AES import failed: %d", static_cast<int>(status));
        return false;
    }
    return true;
}
#endif

}  // namespace

bool aes_ecb_encrypt(uint8_t out[16], const uint8_t key[16], const uint8_t in[16])
{
    if (!out || !key || !in) {
        return false;
    }
#if MBEDTLS_VERSION_MAJOR >= 4
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (!psa_import_aes_key(key_id, key, PSA_ALG_ECB_NO_PADDING, PSA_KEY_USAGE_ENCRYPT)) {
        std::memset(out, 0, 16);
        return false;
    }

    size_t out_len            = 0;
    const psa_status_t status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &out_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS || out_len != 16) {
        M5_LIB_LOGE("PSA AES ECB encrypt failed: %d", static_cast<int>(status));
        std::memset(out, 0, 16);
        return false;
    }
    return true;
#else
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
#endif
}

bool aes_cbc_crypt(uint8_t* out, const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* in, const size_t len,
                   const bool encrypt)
{
    if (!out || !key || !iv_in || (!in && len)) {
        return false;
    }
    if (len % 16 != 0) {
        return false;
    }
    if (len == 0) {
        return true;
    }
#if MBEDTLS_VERSION_MAJOR >= 4
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    if (!psa_import_aes_key(key_id, key, PSA_ALG_CBC_NO_PADDING,
                            encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT)) {
        std::memset(out, 0, len);
        return false;
    }

    std::vector<uint8_t> tmp(len + PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE);

    psa_cipher_operation_t operation = psa_cipher_operation_init();
    psa_status_t status              = encrypt ? psa_cipher_encrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING)
                                               : psa_cipher_decrypt_setup(&operation, key_id, PSA_ALG_CBC_NO_PADDING);
    if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(&operation, iv_in, 16);
    }

    size_t update_len = 0;
    if (status == PSA_SUCCESS) {
        status = psa_cipher_update(&operation, in, len, tmp.data(), len, &update_len);
    }

    size_t finish_len = 0;
    if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(&operation, tmp.data() + update_len, tmp.size() - update_len, &finish_len);
    }

    psa_cipher_abort(&operation);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS || update_len + finish_len != len) {
        M5_LIB_LOGE("PSA AES CBC crypt failed: %d", static_cast<int>(status));
        std::memset(out, 0, len);
        return false;
    }
    std::memcpy(out, tmp.data(), len);
    return true;
#else
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
#endif
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
