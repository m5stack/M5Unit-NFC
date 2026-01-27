/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file secure_zero.hpp
  @brief Secure memory wipe helpers
*/
#pragma once

#include <cstddef>

namespace m5 {
namespace nfc {
namespace crypto {

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
