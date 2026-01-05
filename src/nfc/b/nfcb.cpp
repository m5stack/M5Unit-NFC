/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcb.cpp
  @brief NFC-B definitions
*/
#include "nfcb.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::b;

namespace {

constexpr char name_unknown[]      = "Unknown";
constexpr char name_unclassified[] = "Unclassified";

constexpr const char* name_table[] = {
    name_unknown,  //
    name_unclassified,
};

constexpr uint16_t frame_length_table[9] = {
    16, 24, 32, 40, 48, 64, 96, 128, 256,
};

}  // namespace

namespace m5 {
namespace nfc {
namespace b {

uint16_t maximum_frame_length(const uint8_t protocol[3])
{
    if (protocol && ((protocol[1] >> 4) <= 8)) {
        return frame_length_table[protocol[1] >> 4];
    }
    return 0;
}

//
std::string PICC::pupiAsString() const
{
    char buf[2 * 4 + 1]{};
    uint8_t left{};
    for (uint8_t i = 0; i < 4; ++i) {
        left += snprintf(buf + left, 3, "%02X", this->pupi[i]);
    }
    return std::string(buf);
}

std::string PICC::typeAsString() const
{
    auto idx = m5::stl::to_underlying(this->type);
    return std::string((idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);
}

}  // namespace b
}  // namespace nfc
}  // namespace m5
