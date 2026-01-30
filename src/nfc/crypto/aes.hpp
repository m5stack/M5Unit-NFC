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

bool aes_ecb_encrypt(uint8_t out[16], const uint8_t key[16], const uint8_t in[16]);

bool aes_cbc_crypt(uint8_t* out, const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* in, size_t len,
                   bool encrypt);

bool cmac_subkeys(uint8_t k1[16], uint8_t k2[16], const uint8_t key[16]);

bool cmac_aes_128(uint8_t out[16], const uint8_t key[16], const uint8_t* msg, size_t msg_len);

}  // namespace crypto
}  // namespace nfc
}  // namespace m5
