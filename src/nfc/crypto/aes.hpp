/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file aes.hpp
  @brief AES/CMAC helpers
*/
#pragma once

#include <cstddef>
#include <cstdint>

namespace m5 {
namespace nfc {
namespace crypto {

/*!
  @brief AES-128 ECB encryption of a single 16-byte block
  @param[out] out Encrypted output (16 bytes)
  @param key AES-128 key (16 bytes)
  @param in Plaintext input (16 bytes)
  @return True if successful
 */
bool aes_ecb_encrypt(uint8_t out[16], const uint8_t key[16], const uint8_t in[16]);

/*!
  @brief AES-128 CBC encrypt or decrypt
  @param[out] out Output buffer (same size as in)
  @param key AES-128 key (16 bytes)
  @param iv_in Initialization vector (16 bytes)
  @param in Input buffer
  @param len Input buffer length (must be multiple of 16)
  @param encrypt True for encrypt, false for decrypt
  @return True if successful
 */
bool aes_cbc_crypt(uint8_t* out, const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* in, size_t len,
                   bool encrypt);

/*!
  @brief Generate AES-CMAC subkeys K1 and K2
  @param[out] k1 Subkey K1 (16 bytes)
  @param[out] k2 Subkey K2 (16 bytes)
  @param key AES-128 key (16 bytes)
  @return True if successful
 */
bool cmac_subkeys(uint8_t k1[16], uint8_t k2[16], const uint8_t key[16]);

/*!
  @brief Calculate AES-CMAC (RFC 4493)
  @param[out] out CMAC output (16 bytes)
  @param key AES-128 key (16 bytes)
  @param msg Message buffer
  @param msg_len Message length
  @return True if successful
 */
bool cmac_aes_128(uint8_t out[16], const uint8_t key[16], const uint8_t* msg, size_t msg_len);

}  // namespace crypto
}  // namespace nfc
}  // namespace m5
