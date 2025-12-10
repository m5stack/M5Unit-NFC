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

using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {

constexpr char name_unknown[] = "Unknown";
// Classic 4
constexpr char name_classic_mini[] = "MIFARE Classic Mini";
constexpr char name_classic_1K[]   = "MIFARE Classsic1K";
constexpr char name_classic_2K[]   = "MIFARE Classsic2K";
constexpr char name_classic_4K[]   = "MIFARE Classsic4K";
// Light 5
constexpr char name_ul[]        = "MIFARE Ultralight";
constexpr char name_ul_ev1_11[] = "MIFARE Ultralight EV1 11";
constexpr char name_ul_ev1_21[] = "MIFARE Ultralight EV1 21";
constexpr char name_ul_nano[]   = "MIFARE Ultralight Nano";
constexpr char name_ul_c[]      = "MIFARE UltralightC";
// Plus 11
constexpr char name_plus_2K[] = "MIFARE Plus 2K";
constexpr char name_plus_4K[] = "MIFARE Plus 4K";
constexpr char name_plus_se[] = "MIFARE Plus SE";
// DesFire 3
constexpr char name_desfire_2K[] = "MIFARE DESFire 2K";
constexpr char name_desfire_4K[] = "MIFARE DESFire 4K";
constexpr char name_desfire_8K[] = "MIFARE DESFire 8K";
// NTAG 7
constexpr char name_ntag203[]  = "NTAG 203";
constexpr char name_ntag210u[] = "NTAG 210u";
constexpr char name_ntag210[]  = "NTAG 210";
constexpr char name_ntag212[]  = "NTAG 212";
constexpr char name_ntag213[]  = "NTAG 213";
constexpr char name_ntag215[]  = "NTAG 215";
constexpr char name_ntag216[]  = "NTAG 216";
//
constexpr char name_iso14443_4[] = "ISO14443-4";
constexpr char name_iso18092[]   = "ISO18092";

constexpr const char* name_table[] = {
    name_unknown,                                                                     //
    name_classic_mini, name_classic_1K, name_classic_2K, name_classic_4K,             // Classic
    name_ul,           name_ul_ev1_11,  name_ul_ev1_21,  name_ul_nano,    name_ul_c,  // Light
    name_plus_2K,      name_plus_4K,    name_plus_se,                                 // Plus
    name_desfire_2K,   name_desfire_4K, name_desfire_8K,                              // DESFire
    name_ntag203,      name_ntag210u,   name_ntag210,                                 // NTAG
    name_ntag212,      name_ntag213,    name_ntag215,                                 // NTAG
    name_ntag216,                                                                     // NTAG
    name_iso14443_4,   name_iso18092,                                                 // Others
};

//
constexpr char name_sub_plus_none[]         = "";
constexpr char name_sub_plus_ev1[]          = "EV1";
constexpr char name_sub_plus_ev2[]          = "EV2";
constexpr char name_sub_plus_s[]            = "S";
constexpr char name_sub_plus_x[]            = "X";
constexpr const char* name_sub_plus_table[] = {name_sub_plus_none, name_sub_plus_ev1, name_sub_plus_ev2,
                                               name_sub_plus_s, name_sub_plus_x};

//
constexpr char name_sub_desfire_ev1[]          = "EV1";
constexpr char name_sub_desfire_ev2[]          = "EV2";
constexpr char name_sub_desfire_ev3[]          = "EV3";
constexpr const char* name_sub_desfire_table[] = {name_sub_desfire_ev1, name_sub_desfire_ev2, name_sub_desfire_ev3};

// included system area
constexpr uint16_t max_block_table[] = {0,                                 // Unknown
                                        20,  64,  128, 256,                // Classic
                                        16,  20,  40,  14,  48,            // Light
                                        128, 256, 64,                      // Plus
                                        0,   0,   0,                       // DESFire (Not has blocks, File base system)
                                        42,  20,  16,  40,  45, 135, 231,  // NTAG
                                        0,   0};

// [first/last]
constexpr uint8_t user_block_table[][2] = {
    {0, 0},  // Unknown
    // Classic
    {1, 18},   // Exclusive 0 (Manufacturer Block) and last 1 block (Sector Trailer)
    {1, 62},   // Exclusive 0 (Manufacturer Block) and last 1 block (Sector Trailer)
    {1, 126},  // Exclusive 0 (Manufacturer Block) and last 1 block (Sector Trailer)
    {1, 254},  // Exclusive 0 (Manufacturer Block) and last 1 block (Sector Trailer)
    // Light
    {4, 15},  // Exclusive 0-3 and last 4 pages
    {4, 15},  // Exclusive 0-3 and last 4 pages
    {4, 35},  // Exclusive 0-3 and last 5 pages
    {4, 13},  // Exclusive 0-3
    {4, 39},  // Exclusive 0-3 and last 8 pages
    // Plus
    {1, 126},
    {1, 254},
    {1, 62},
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
    0,  0,  0,  0,  0,        // Light
    32, 40, 16,               // Plus
    0,  0,  0,                // Desfire
    0,  0,  0,  0,  0, 0, 0,  // NTAG
    0,  0,
};

constexpr uint16_t user_area_size_table[] = {
    // bytes
    0,                                      // Unknown
    240,  752,  1504, 3440,                 // Classic
    48,   48,   128,  40,   144,            // Light
    1504, 3440, 752,                        // Plus
    0,    0,    0,                          // Desfire
    144,  48,   144,  208,  144, 504, 888,  // NTAG
    0,    0,
};

constexpr NFCForumTag nfc_forum_tag_table[] = {
    NFCForumTag::None,                                                                                   //
    NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,                       // Classic
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,  // Light
    NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,                                           // Plus
    NFCForumTag::Type4, NFCForumTag::Type4, NFCForumTag::Type4,                                          // DESFire
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,                      // NTAG
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,                                          // NTAG
    NFCForumTag::None,  NFCForumTag::None,                                                               //
};

struct Historical {
    const std::array<uint8_t, 7>& h;
    const Type t;
    const SubTypePlus sub;
};
constexpr Historical historical_table_sak18[] = {
    {historical_bytes_mifare_plus_s, Type::MIFARE_Plus_4K, SubTypePlus::S},  // S 4K SL1
    {historical_bytes_mifare_plus_x, Type::MIFARE_Plus_4K, SubTypePlus::X},  // X 4K SL1
};
constexpr Historical historical_table_sak08[] = {
    {historical_bytes_mifare_plus_s, Type::MIFARE_Plus_2K, SubTypePlus::S},  // S 2K SL1
    {historical_bytes_mifare_plus_x, Type::MIFARE_Plus_2K, SubTypePlus::X},  // X 2K SL1
};
constexpr Historical historical_table_sak20[] = {
    {historical_bytes_mifare_plus_s, Type::MIFARE_Plus_2K, SubTypePlus::S},       // S 2K/4K SL1
    {historical_bytes_mifare_plus_x, Type::MIFARE_Plus_2K, SubTypePlus::X},       // X 2K/4K SL1
    {historical_bytes_mifare_plus_se0, Type::MIFARE_Plus_SE, SubTypePlus::None},  // SE
    {historical_bytes_mifare_plus_se1, Type::MIFARE_Plus_SE, SubTypePlus::None},  // SE
    {historical_bytes_mifare_plus_se2, Type::MIFARE_Plus_SE, SubTypePlus::None},  // SE
};

}  // namespace

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
    return supports_NFC(t) ? 4 : is_mifare(t) ? 16 : 0;
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
    if (sak & 0x04 /*b3*/) {  // PICC uncompleted
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

Type version3_to_type(const uint8_t info[8])
{
    if (!info) {
        return Type::Unknown;
    }

    const uint8_t hw_type    = info[2];
    const uint8_t hw_version = info[4];
    const uint8_t size       = info[6];

    // m5::utility::log::dump(info,10,false);

    if (info[0] != 0x00 || info[1] != 0x04 /*NXP*/ || info[7] != 0x03 /* ISO14443-A*/) {
        return Type::Unknown;
    }
    if (hw_type == 0x04 /* NTAG */) {
        return (size == 0x0E)   ? Type::NTAG_212
               : (size == 0x0F) ? Type::NTAG_213
               : (size == 0x11) ? Type::NTAG_215
               : (size == 0x13) ? Type::NTAG_216
               : (size == 0x0B) ? ((hw_version == 0x02) ? Type::NTAG_210u : Type::NTAG_210)
                                : Type::Unknown;
    }
    if (info[2] == 0x03 /*Ultralight */) {
        // Ultralight EV1 or Nano
        return (hw_version == 0x01)   ? (size == 0x0B ? Type::MIFARE_Ultralight_EV1_1
                                                      : (size == 0x0E ? Type::MIFARE_Ultralight_EV1_2 : Type::Unknown))
               : (hw_version == 0x02) ? Type::MIFARE_Ultralight_Nano
                                      : Type::Unknown;
    }
    return Type::Unknown;
}

Type version4_to_type(uint8_t& sub, const uint8_t info[8])
{
    Type type = Type::Unknown;
    sub       = 0;

    if (!info) {
        return type;
    }

    const uint8_t hw_type    = info[2];
    const uint8_t hw_version = info[4];
    const uint8_t size       = info[6];

    //M5_LIB_LOGE(">>>> hw_type:%02X hw_ver:%02X size:%02X", hw_type, hw_version, size);

    if (hw_type == 0x02 || hw_type == 0x82) {
        switch (hw_version) {
            case 0x11:  // EV1
                sub = m5::stl::to_underlying(SubTypePlus::EV1);
                break;
            case 0x22:  // EV2
                sub = m5::stl::to_underlying(SubTypePlus::EV2);
                break;
            default:  // ERROR
                return type;
        }
        switch (size) {
            case 0x16:  // 2K
                type = Type::MIFARE_Plus_2K;
                break;
            case 0x18:  // 4K
                type = Type::MIFARE_Plus_4K;
                break;
            default:  // ERROR
                break;
        }
        return type;
    }
#if 0
    if (hw_type == 0x01 || hw_type == 0x81) {
        switch (hw_verison & 0x0F) {
            case 0x01:  // EV1
            case 0x02:  // EV2
            case 0x03:  // EV3
                switch (size) {
                    case 0x10:
                        return Tupe::MIFARE_DESFire_256B;
                    case 0x16:
                        return Tupe::MIFARE_DESFire_2K;
                    case 0x18:
                        return Tupe::MIFARE_DESFire_4K;
                    case 0x1A:
                        return Tupe::MIFARE_DESFire_8K;
                    case 0x1C:
                        return Tupe::MIFARE_DESFire_16K;
                    case 0x1E:
                        return Tupe::MIFARE_DESFire_32K;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }

    if (hw_type == 0x08) {
        return Type::MIFARE_DESFire_Light;
    }
    if (hw_type == 0x04) {
        return Type::NTAG_4XX;
    }
#endif
    return type;
}

Type historical_bytes_to_type_sak18(uint8_t& sub, const uint8_t* bytes, const uint8_t len)
{
    return Type::Unknown;
}

Type historical_bytes_to_type_sak08(uint8_t& sub, const uint8_t* bytes, const uint8_t len)
{
    return Type::Unknown;
}
Type historical_bytes_to_type_sak20(uint8_t& sub, const uint8_t* bytes, const uint8_t len, const uint16_t atqa)
{
    Type t = Type::Unknown;
    sub    = 0;

    if (bytes && len >= 7) {
        // m5::utility::log::dump(bytes, len, false);
        for (auto&& h : historical_table_sak20) {
            // m5::utility::log::dump(h.h.data(), h.h.size(), false);
            if (memcmp(h.h.data(), bytes, h.h.size()) == 0) {
                t   = h.t;
                sub = m5::stl::to_underlying(h.sub);
                break;
            }
        }
        if (t == Type::MIFARE_Plus_2K) {
            t = static_cast<Type>(m5::stl::to_underlying(t) + ((atqa & 0x000F) == 0x02));  // 2/4K
        }
    }
    return t;
}

m5::nfc::NFCForumTag get_nfc_forum_tag_type(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return nfc_forum_tag_table[idx < m5::stl::size(max_block_table) ? idx : 0];
}

//
std::string PICC::uidAsString() const
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

std::string PICC::typeAsString() const
{
    auto idx = m5::stl::to_underlying(this->type);
    auto s   = std::string((this->size && idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);

    if (isMifarePlus()) {
        idx = m5::stl::to_underlying(sub_type_plus);
        auto ss =
            std::string((this->size && idx <= m5::stl::size(name_sub_plus_table)) ? name_sub_plus_table[idx] : "");
        if (ss[0]) {
            s += " ";
            s += ss;
        }
    }
    return s;
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
