/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file secure_zero.hpp
  @brief Secure memory wipe helpers
*/
#ifndef M5_UNIT_NFC_NFC_CRYPTO_SECURE_ZERO_HPP
#define M5_UNIT_NFC_NFC_CRYPTO_SECURE_ZERO_HPP

#include <cstddef>

namespace m5 {
namespace nfc {
namespace crypto {

/*!
  @brief Securely wipe a memory region (volatile-safe; not optimized away)
  @param p Pointer to memory to wipe
  @param n Number of bytes to wipe
 */
inline void secure_zero(void* p, const size_t n)
{
    if (!p || n == 0) {
        return;
    }
    volatile unsigned char* v = reinterpret_cast<volatile unsigned char*>(p);
    for (size_t i = 0; i < n; ++i) {
        v[i] = 0;
    }
}

}  // namespace crypto
}  // namespace nfc
}  // namespace m5
#endif
