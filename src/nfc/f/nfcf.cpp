/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcf.cpp
  @brief NFC-F definitions
*/

#include "nfcf.hpp"
#include <M5Utility.hpp>

namespace {
std::string to_string(const uint8_t* p, const uint8_t size)
{
    char buf[2 * size + 1]{};
    if (p && size) {
        uint8_t left{};
        for (uint_fast8_t i = 0; i < size; ++i) {
            left += snprintf(buf + left, 3, "%02X", p[i]);
        }
    }
    return std::string(buf);
}
}  // namespace

namespace m5 {
namespace nfc {
namespace f {

std::string PICC::idmAsString() const
{
    return to_string(this->idm.data(), this->idm.size());
}

std::string PICC::pmmAsString() const
{
    return to_string(this->pmm.data(), this->pmm.size());
}

}  // namespace f
}  // namespace nfc
}  // namespace m5
