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
constexpr char name_unknown[]      = "Unknown";
constexpr char name_standard[]     = "FeliCa Standard";
constexpr char name_lite[]         = "FeliCa Lite";
constexpr char name_lite_s[]       = "FeliCa Lite-S";
constexpr char name_plug[]         = "FeliCa Plug";
constexpr const char* name_table[] = {name_unknown, name_standard, name_lite, name_lite_s, name_plug};

// Maximum block number (Note that there are gaps in the blocks)
constexpr uint16_t max_block_table[] = {0, 0, 0x88, 0xA0, 0};
// Maximum number of blocks that can be read simultaneously
constexpr uint16_t max_read_block_table[] = {0, 8, 4, 4, 4};
// Maximum number of blocks that can be write simultaneously
constexpr uint16_t max_write_block_table[] = {0, 1, 1, 1, 1};

// [first/last]
constexpr uint8_t user_block_table[][2] = {{0XFF, 0XFF}, {0XFF, 0XFF}, {0x00, 0x0D}, {0x00, 0x0D}, {0XFF, 0XFF}};

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

uint16_t get_maximum_block(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return max_block_table[idx < m5::stl::size(max_block_table) ? idx : 0];
}

uint16_t get_number_of_user_blocks(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    auto p      = user_block_table[idx < m5::stl::size(user_block_table) ? idx : 0];
    uint8_t sz  = p[1] - p[0];
    return sz ? (sz + 1) : 0;
}

uint16_t get_first_user_block(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return user_block_table[idx < m5::stl::size(user_block_table) ? idx : 0][0];
}

uint16_t get_last_user_block(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return user_block_table[idx < m5::stl::size(user_block_table) ? idx : 0][1];
}

uint8_t get_maxumum_read_blocks(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return max_read_block_table[idx < m5::stl::size(max_block_table) ? idx : 0];
}

uint8_t get_maxumum_write_blocks(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return max_write_block_table[idx < m5::stl::size(max_block_table) ? idx : 0];
}

//
std::string PICC::idmAsString() const
{
    return to_string(this->idm.data(), this->idm.size());
}

std::string PICC::pmmAsString() const
{
    return to_string(this->pmm.data(), this->pmm.size());
}

std::string PICC::typeAsString() const
{
    const auto idx = m5::stl::to_underlying(this->type);
    return std::string((idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);
}

}  // namespace f
}  // namespace nfc
}  // namespace m5
