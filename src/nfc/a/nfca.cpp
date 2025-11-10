/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfca.cpp
  @brief NFC-A definitions
*/
#include "nfca.hpp"
#include <M5Utility.hpp>

namespace {
constexpr char name_unknown[]       = "Unknown";
constexpr char name_classic_mini[]  = "MIFARE Classic Mini";
constexpr char name_classic_1K[]    = "MIFARE Classsic1K";
constexpr char name_classic_2K[]    = "MIFARE Classsic2K";
constexpr char name_classic_4K[]    = "MIFARE Classsic4K";
constexpr char name_ultra_light[]   = "MIFARE Ultralight";
constexpr char name_ultra_light_c[] = "MIFARE UltralightC";
constexpr char name_plus_2K[]       = "MIFARE Plus2K";
constexpr char name_plus_4K[]       = "MIFARE Plus4K";
constexpr char name_desfire_2K[]    = "MIFARE DESFire2K";
constexpr char name_desfire_4K[]    = "MIFARE DESFire4K";
constexpr char name_desfire_8K[]    = "MIFARE DESFire8K";
constexpr char name_ntag203[]       = "NTAG 203";
constexpr char name_ntag210u[]      = "NTAG 210u";
constexpr char name_ntag210[]       = "NTAG 210";
constexpr char name_ntag212[]       = "NTAG 212";
constexpr char name_ntag213[]       = "NTAG 213";
constexpr char name_ntag215[]       = "NTAG 215";
constexpr char name_ntag216[]       = "NTAG 216";
constexpr char name_iso14443_4[]    = "ISO14443-4";
constexpr char name_iso18092[]      = "ISO18092";
constexpr const char* name_table[]  = {
    name_unknown,                                                             //
    name_classic_mini, name_classic_1K,    name_classic_2K, name_classic_4K,  // Classic
    name_ultra_light,  name_ultra_light_c,                                    // Light
    name_plus_2K,      name_plus_4K,                                          // Plus
    name_desfire_2K,   name_desfire_4K,    name_desfire_8K,                   // DESFire
    name_ntag203,      name_ntag210u,      name_ntag210,                      // NTAG
    name_ntag212,      name_ntag213,       name_ntag215,                      // NTAG
    name_ntag216,                                                             // NTAG
    name_iso14443_4,   name_iso18092,                                         //
};

// included system area
constexpr uint16_t max_block_table[] = {0,                                 // Unknown
                                        20,  64,  128, 256,                // Classic
                                        16,  48,                           // Light
                                        128, 256,                          // Plus
                                        0,   0,   0,                       // DESFire (Not has blocks, File base system)
                                        42,  20,  16,  40,  45, 135, 231,  // NTAG
                                        0,   0};

// [first/last]
constexpr uint8_t user_block_table[][2] = {
    {0, 0},  // Unknown
    // Classic
    {1, 18},   // Exclusive 0 (Manufacturer Block)  and last 1 block (Sector Trailer)
    {1, 62},   // Exclusive 0 (Manufacturer Block)  and last 1 block (Sector Trailer)
    {1, 126},  // Exclusive 0 (Manufacturer Block)  and last 1 block (Sector Trailer)
    {1, 254},  // Exclusive 0 (Manufacturer Block)  and last 1 block (Sector Trailer)
    // Light
    {4, 15},  // Exclusive 0-3 and last 4 pages
    {4, 39},  // Exclusive 0-3 and last 8 pages
    // Plus
    {0, 0},
    {0, 0},
    // DESFire
    {0, 0},
    {0, 0},
    {0, 0},
    // NTAG
    {4, 39},   // 203 Exclusive 0-3 and last 2 pages
    {4, 15},   // 210u Exclusive 0-3
    {4, 15},   // 210 Exclusive 0-3 and last 4 page
    {4, 35},   // 212 Exclusive 0-3 and last 5 pages
    {4, 39},   // 213 Exclusive 0-3 and last 5 pages
    {4, 129},  // 215 Exclusive 0-3 and last 5 pages
    {4, 225},  // 216 Exclusive 0-3 and last 5 pages
    //
    {0, 0},
    {0, 0},
};

constexpr uint8_t max_sector_table[] = {
    0,                        // Unknown
    5,  16, 32, 40,           // Classic
    0,  0,                    // Light
    32, 40,                   // Plus
    0,  0,  0,                // Desfire
    0,  0,  0,  0,  0, 0, 0,  // NTAG
    0,  0,
};

constexpr uint16_t user_area_size_table[] = {
    // bytes
    0,                                      // Unknown
    240,  752,  1504, 3440,                 // Classic
    48,   144,                              // Light
    1504, 3440,                             // Plus
    0,    0,    0,                          // Desfire
    144,  48,   144,  208,  144, 504, 888,  // NTAG
    0,    0,
};

}  // namespace

using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace m5 {
namespace nfc {
namespace a {

uint16_t get_number_of_blocks(const Type t)
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

uint16_t get_user_area_size(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return user_area_size_table[idx < m5::stl::size(user_area_size_table) ? idx : 0];
}

uint16_t get_unit_size(const Type t)
{
    return is_mifare_classic(t) ? 16 : supports_NFC(t) ? 4 : 0;
}

uint16_t get_number_of_sectors(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return max_sector_table[idx < m5::stl::size(max_sector_table) ? idx : 0];
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

bool is_user_block(const Type t, const uint16_t block)
{
    if (is_mifare_classic(t)) {
        return (block != 0) &&                     // Not Manufacturer block
               !is_sector_trailer_block(block) &&  // Not Sector trailer
               block <= get_last_user_block(t);    // In range
    } else if (supports_NFC(t)) {
        return (block >= get_first_user_block(t)) && (block <= get_last_user_block(t));
    }
    return false;
}

Type sak_to_type(const uint8_t sak)
{
    if (sak & 0x02 /*b2*/) {  // RFU?
        return Type::Unknown;
    }
    if (sak & 0x04 /*b3*/) {  // UID uncompleted
        return Type::Unknown;
    }

    if (sak & 0x08 /*b4*/) {
        // Bit 4 Yes
        if (sak & 0x10 /*b5*/) {
            // Bit 5 Yes
            if (sak & 0x01 /*b1*/) {
                return Type::MIFARE_Classic_2K;  // 0x19
            }
            if (sak & 0x20 /*b6*/) {
                return Type::MIFARE_Classic_4K;  // 0x38 SmartMX with
            }
            return Type::MIFARE_Classic_4K /* 0x18 */;  // or Plus (Need check RATS)
        }
        // Bit 5 No
        if (sak & 0x01 /*b1*/) {
            return Type::MIFARE_Classic_Mini;  // 0x09
        }
        if (sak & 0x20 /*b6*/) {
            return Type::MIFARE_Classic_1K;  // 0x28 SmartMX with
        }
        return Type::MIFARE_Classic_1K /* 0x08 */;  // or Plus (Need check RATS)
    }

    // Bit 4 No
    if (sak & 0x10 /*b5*/) {
        // Bit 5 Yes
        return (sak & 0x01) ? Type::MIFARE_Plus_4K /* 0x11*/ : Type::MIFARE_Plus_2K /* 0x10*/;
    }
    // Bit 5 No
    if (sak & 0x01 /*b1*/) {
        // TagNPlay
        return Type::Unknown;
    }
    // Bit 1 No
    if (sak & 0x20 /*b6*/) {
        return Type::ISO_14443_4;  // Additional detection requires RATS and GetVersionL4
    }
    // Bit 6 No
    return Type::MIFARE_Ultralight;  // or UltralightC or NTAG (Need GetVersionL3)
}

Type version_to_type(const uint8_t info[10])
{
    if (!info) {
        return Type::Unknown;
    }

    if (info[0] != 0x00 || info[1] != 0x04 /*NXP*/ || info[7] != 0x03 /* ISO14443-A*/) {
        return Type::Unknown;
    }
    if (info[2] == 0x04 /* NXP */) {
        // info[6] Storage size code
        return (info[6] == 0x0E)   ? Type::NTAG_212
               : (info[6] == 0x0F) ? Type::NTAG_213
               : (info[6] == 0x11) ? Type::NTAG_215
               : (info[6] == 0x13) ? Type::NTAG_216
               : (info[6] == 0x0B) ? ((info[4] == 0x02) ? Type::NTAG_210u : Type::NTAG_210)
                                   : Type::Unknown;
    }
    if (info[2] == 0x03 /*Ultralight */) {
        // Ultralight EV1, Nano
        return Type::Unknown;
    }
    return Type::Unknown;
}

std::string UID::uidAsString() const
{
    char buf[2 * 10 + 1]{};
    if (this->size <= 10) {
        uint8_t left{};
        for (uint8_t i = 0; i < this->size; ++i) {
            left += snprintf(buf + left, 3, "%02X", this->uid[i]);
        }
    }
    return std::string(buf);
}

std::string UID::typeAsString() const
{
    const auto idx = m5::stl::to_underlying(this->type);
    return std::string((this->size && idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);
}

uint8_t calculate_bcc8(const uint8_t* data, const uint32_t len)
{
    uint8_t bcc{};
    if (data && len) {
        for (uint32_t i = 0; i < len; ++i) {
            bcc ^= data[i];
        }
    }
    return bcc;
}
}  // namespace a
}  // namespace nfc
}  // namespace m5
