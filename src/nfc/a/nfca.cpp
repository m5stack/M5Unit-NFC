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
// Classic
constexpr char name_classic_mini[] = "MIFARE Classic Mini";
constexpr char name_classic_1K[]   = "MIFARE Classsic1K";
constexpr char name_classic_2K[]   = "MIFARE Classsic2K";
constexpr char name_classic_4K[]   = "MIFARE Classsic4K";
// Light
constexpr char name_ul[]        = "MIFARE Ultralight";
constexpr char name_ul_ev1_11[] = "MIFARE Ultralight EV1 11";
constexpr char name_ul_ev1_21[] = "MIFARE Ultralight EV1 21";
constexpr char name_ul_nano[]   = "MIFARE Ultralight Nano";
constexpr char name_ul_c[]      = "MIFARE UltralightC";
// NTAG 2xx
constexpr char name_ntag203[]  = "NTAG 203";
constexpr char name_ntag210u[] = "NTAG 210u";
constexpr char name_ntag210[]  = "NTAG 210";
constexpr char name_ntag212[]  = "NTAG 212";
constexpr char name_ntag213[]  = "NTAG 213";
constexpr char name_ntag215[]  = "NTAG 215";
constexpr char name_ntag216[]  = "NTAG 216";
//
constexpr char name_st25ta_512b[] = "ST25TA 512B";
constexpr char name_st25ta_2k[]   = "ST25TA 2K";
constexpr char name_st25ta_16k[]  = "ST25TA 16K";
constexpr char name_st25ta_64k[]  = "ST25TA 64K";
//
constexpr char name_iso14443_4[] = "ISO14443-4";
// Plus
constexpr char name_plus_2K[] = "MIFARE Plus 2K";
constexpr char name_plus_4K[] = "MIFARE Plus 4K";
constexpr char name_plus_se[] = "MIFARE Plus SE";
// DesFire
constexpr char name_desfire_2K[]    = "MIFARE DESFire 2K";
constexpr char name_desfire_4K[]    = "MIFARE DESFire 4K";
constexpr char name_desfire_8K[]    = "MIFARE DESFire 8K";
constexpr char name_desfire_light[] = "MIFARE DESFire Light";
// NTAG 4xx
constexpr char name_ntag_4xx[] = "NTAG 4XX";
//
constexpr char name_iso18092[] = "ISO18092";

constexpr const char* name_table[] = {
    name_unknown,                                                                        //
    name_classic_mini, name_classic_1K, name_classic_2K, name_classic_4K,                // Classic
    name_ul,           name_ul_ev1_11,  name_ul_ev1_21,  name_ul_nano,       name_ul_c,  // Light
    name_ntag203,      name_ntag210u,   name_ntag210,                                    // NTAG 2xx
    name_ntag212,      name_ntag213,    name_ntag215,                                    // NTAG 2xx
    name_ntag216,                                                                        // NTAG 2xx
    name_st25ta_512b,  name_st25ta_2k,  name_st25ta_16k, name_st25ta_64k,                // ST25A
    name_iso14443_4,                                                                     // 14443-4
    name_plus_2K,      name_plus_4K,    name_plus_se,                                    // Plus
    name_desfire_2K,   name_desfire_4K, name_desfire_8K, name_desfire_light,             // DESFire
    name_ntag_4xx,                                                                       // NTAG 4xx
    name_iso18092,                                                                       //
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
constexpr char name_sub_desfire_none[]         = "";
constexpr char name_sub_desfire_ev1[]          = "EV1";
constexpr char name_sub_desfire_ev2[]          = "EV2";
constexpr char name_sub_desfire_ev3[]          = "EV3";
constexpr const char* name_sub_desfire_table[] = {name_sub_desfire_none, name_sub_desfire_ev1, name_sub_desfire_ev2,
                                                  name_sub_desfire_ev3};

// included system area
constexpr uint16_t max_block_table[] = {0,                                 // Unknown
                                        20,  64,  128, 256,                // Classic
                                        16,  20,  40,  14,  48,            // Light
                                        42,  20,  16,  40,  45, 135, 231,  // NTAG 2xx
                                        0,   0,   0,   0,                  // ST25TA (File base system)
                                        0,                                 // 14443-4
                                        128, 256, 64,                      // Plus
                                        0,   0,   0,   0,                  // DESFire (File base system)
                                        0,                                 // NTAG 4xx
                                        0};

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
    // NTAG 2xx
    {4, 39},   // 203 Exclusive 0-3 and last 2 pages
    {4, 15},   // 210u Exclusive 0-3
    {4, 15},   // 210 Exclusive 0-3 and last 4 page
    {4, 35},   // 212 Exclusive 0-3 and last 5 pages
    {4, 39},   // 213 Exclusive 0-3 and last 5 pages
    {4, 129},  // 215 Exclusive 0-3 and last 5 pages
    {4, 225},  // 216 Exclusive 0-3 and last 5 pages
    // ST25TA
    {0, 0},
    {0, 0},
    {0, 0},
    {0, 0},
    // 14443-4
    {0, 0},
    // Plus
    {1, 126},
    {1, 254},
    {1, 62},
    // DESFire
    {0, 0},
    {0, 0},
    {0, 0},
    {0, 0},
    // NTAG 4xx
    {0, 0},
    //
    {0, 0},
};

constexpr uint8_t max_sector_table[] = {
    0,                        // Unknown
    5,  16, 32, 40,           // Classic
    0,  0,  0,  0,  0,        // Light
    0,  0,  0,  0,  0, 0, 0,  // NTAG
    0,  0,  0,  0,            // ST25TA
    0,                        //
    32, 40, 16,               // Plus
    0,  0,  0,  0,            // Desfire
    0,                        // NTAG 4xx
    0,
};

constexpr uint16_t user_area_size_table[] = {
    // bytes
    0,                                      // Unknown
    240,  752,  1504, 3440,                 // Classic
    48,   48,   128,  40,   144,            // Light
    144,  48,   144,  208,  144, 504, 888,  // NTAG
    64,   256,  2048, 8192,                 // ST25
    0,                                      //
    1504, 3440, 752,                        // Plus
    2048, 4096, 8192, 256,                  // Desfire, Light:The total is 512, but the maximum per file is 256
    0,                                      // NTAG 4xx
    0,
};

// TODO Support DESFire Light
constexpr NFCForumTag nfc_forum_tag_table[] = {
    NFCForumTag::None,                                                                                   //
    NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,                       // Classic
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,  // Light
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,                      // NTAG 2xx
    NFCForumTag::Type2, NFCForumTag::Type2, NFCForumTag::Type2,                                          // NTAG 2xx
    NFCForumTag::Type4, NFCForumTag::Type4, NFCForumTag::Type4, NFCForumTag::Type4,                      // ST25TA
    NFCForumTag::None,                                                                                   //
    NFCForumTag::None,  NFCForumTag::None,  NFCForumTag::None,                                           // Plus
    NFCForumTag::Type4, NFCForumTag::Type4, NFCForumTag::Type4, NFCForumTag::None,                       // DESFire
    NFCForumTag::Type4,                                                                                  // NTAG 4xx
    NFCForumTag::None,                                                                                   //
};

struct EmulationSetting {
    uint16_t atqa;
    uint8_t sak;
};
constexpr EmulationSetting emulation_settings[] = {
    {0, 0},                                                                          //
    {0x0004, 0x09}, {0x0004, 0x08}, {0x0002, 0x19}, {0x0002, 0x18},                  // Classic
    {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00},  // Light
    {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00},                  // NTAG 2xx
    {0x0044, 0x00}, {0x0044, 0x00}, {0x0044, 0x00},                                  // NTAG 2xx
    {0x0000, 0x00}, {0x0000, 0x00}, {0x0000, 0x00}, {0x0000, 0x00},                  // ST25TA
    {0x0000, 0x20},                                                                  //
    {0x0000, 0x20}, {0x0000, 0x20}, {0x0000, 0x20},                                  // Plus
    {0x0344, 0x20}, {0x0344, 0x20}, {0x0344, 0x20}, {0x0344, 0x20},                  // DESFire
    {0x0000, 0x20},                                                                  //
    {0x0000, 0x00},                                                                  //
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

// GetVersionL3 response for emulation
constexpr uint8_t ver3_ul_ev11[8]   = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0B, 0x03};
constexpr uint8_t ver3_ul_ev21[8]   = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0E, 0x03};
constexpr uint8_t ver3_ul_nano[8]   = {0x00, 0x04, 0x03, 0x01, 0x02, 0x00, 0x0B, 0x03};
constexpr uint8_t ver3_ntag_210[8]  = {0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0B, 0x03};
constexpr uint8_t ver3_ntag_210u[8] = {0x00, 0x04, 0x04, 0x01, 0x02, 0x00, 0x0B, 0x03};
constexpr uint8_t ver3_ntag_212[8]  = {0x00, 0x04, 0x04, 0x01, 0x01, 0x00, 0x0E, 0x03};
constexpr uint8_t ver3_ntag_213[8]  = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
constexpr uint8_t ver3_ntag_215[8]  = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
constexpr uint8_t ver3_ntag_216[8]  = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03};

constexpr const uint8_t* emu_ver3_table[] = {
    nullptr,                                                                                             //
    nullptr, nullptr,        nullptr,       nullptr,                                                     // Classic
    nullptr, ver3_ul_ev11,   ver3_ul_ev21,  ver3_ul_nano,  nullptr,                                      // Light
    nullptr, ver3_ntag_210u, ver3_ntag_210, ver3_ntag_212, ver3_ntag_213, ver3_ntag_215, ver3_ntag_216,  // NTAG2xx
    nullptr, nullptr,        nullptr,       nullptr,                                                     // ST25TA
    nullptr,                                                                                             //
    nullptr, nullptr,        nullptr,                                                                    // Plus
    nullptr, nullptr,        nullptr,       nullptr,                                                     // DESFire
    nullptr,                                                                                             //
    nullptr,                                                                                             //
};

Type historical_bytes_to_type_sak18(uint8_t& sub, const uint8_t* bytes, const uint8_t len)
{
    return Type::Unknown;
}

Type historical_bytes_to_type_sak08(uint8_t& sub, const uint8_t* bytes, const uint8_t len)
{
    return Type::Unknown;
}

Type historical_bytes_to_type_sak20(uint8_t& sub, const uint16_t atqa, const uint8_t* bytes, const uint8_t len)
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
    return is_file_base_file_system(t) ? 0 : (supports_NFC(t) ? 4 : (is_mifare(t) ? 16 : 0));
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

file_system_feature_t get_file_system_feature(const Type t)
{
    if (is_mifare_desfire(t)) {
        return (t == Type::MIFARE_DESFire_Light ? FILE_SYSTEM_DESFIRE_LIGHT : FILE_SYSTEM_DESFIRE) |
               FILE_SYSTEM_ISO7816_4;
    } else if (is_st25ta(t) || is_iso14443_4(t)) {
        return FILE_SYSTEM_ISO7816_4;
    } else if (t != Type::Unknown) {
        return FILE_SYSTEM_FLAT_MEMORY;
    }
    return 0u;
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

Type version3_to_type(const uint8_t ver[8])
{
    if (!ver) {
        return Type::Unknown;
    }

    const uint8_t hw_type    = ver[2];
    const uint8_t hw_version = ver[4];
    const uint8_t size       = ver[6];

    // m5::utility::log::dump(ver,8,false);

    if (ver[0] != 0x00 || ver[1] != 0x04 /*NXP*/ || ver[7] != 0x03 /* ISO14443-A*/) {
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
    if (ver[2] == 0x03 /*Ultralight */) {
        // Ultralight EV1 or Nano
        return (hw_version == 0x01)   ? (size == 0x0B ? Type::MIFARE_Ultralight_EV1_1
                                                      : (size == 0x0E ? Type::MIFARE_Ultralight_EV1_2 : Type::Unknown))
               : (hw_version == 0x02) ? Type::MIFARE_Ultralight_Nano
                                      : Type::Unknown;
    }
    return Type::Unknown;
}

Type version4_to_type(uint8_t& sub, const uint8_t ver[8])
{
    Type type = Type::Unknown;
    sub       = 0;

    if (!ver) {
        return type;
    }

    const uint8_t hw_type    = ver[1];
    const uint8_t hw_version = ver[3];
    const uint8_t size       = ver[5];
    M5_LIB_LOGV("hw_type:%02X hw_ver:%02X size:%02X", hw_type, hw_version, size);

    // Plus
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

    // DESFire
    if (hw_type == 0x01 || hw_type == 0x81) {
        switch (hw_version & 0x0F) {
            case 0x01:  // EV1
                sub = m5::stl::to_underlying(SubTypeDESFire::EV1);
                break;
            case 0x02:  // EV2
                sub = m5::stl::to_underlying(SubTypeDESFire::EV2);
                break;
            case 0x03:  // EV3
                sub = m5::stl::to_underlying(SubTypeDESFire::EV3);
                break;
            default:
                break;
        }
        switch (size) {
            // case 0x10:
            //     return Type::MIFARE_DESFire_256B;
            case 0x16:
                type = Type::MIFARE_DESFire_2K;
                break;
            case 0x18:
                type = Type::MIFARE_DESFire_4K;
                break;
            case 0x1A:
                type = Type::MIFARE_DESFire_8K;
                break;
                // case 0x1C:
                //  return Tupe::MIFARE_DESFire_16K;
                // case 0x1E:
                // return Tupe::MIFARE_DESFire_32K;
            default:
                break;
        }
    }
    if (hw_type == 0x08) {
        return Type::MIFARE_DESFire_Light;
    }

    // NTAG4xx
    if (hw_type == 0x04) {
        return Type::NTAG_4XX;
    }
    return type;
}

Type historical_bytes_to_type(uint8_t& sub, const uint16_t atqa, const uint8_t sak, const uint8_t* bytes,
                              const uint8_t len)
{
    switch (sak) {
        case 0x20:
            return historical_bytes_to_type_sak20(sub, atqa, bytes, len);
        case 0x18:
            return historical_bytes_to_type_sak18(sub, bytes, len);
        case 0x08:
            return historical_bytes_to_type_sak08(sub, bytes, len);
        default:
            break;
    }
    return Type::Unknown;
}

const uint8_t* get_version3_response(const Type t)
{
    return emu_ver3_table[m5::stl::to_underlying(t)];
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

//
m5::nfc::NFCForumTag get_nfc_forum_tag_type(const Type t)
{
    uint8_t idx = m5::stl::to_underlying(t);
    return nfc_forum_tag_table[idx < m5::stl::size(max_block_table) ? idx : 0];
}

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
    if (isMifareDESFire()) {
        idx     = m5::stl::to_underlying(sub_type_desfire);
        auto ss = std::string((this->size && idx <= m5::stl::size(name_sub_desfire_table)) ? name_sub_desfire_table[idx]
                                                                                           : "");
        if (ss[0]) {
            s += " ";
            s += ss;
        }
    }
    return s;
}

bool PICC::emulate(const Type t, const uint8_t* uid, const uint8_t uid_len)
{
    if (t == Type::Unknown || !uid || !(uid_len == 4 || uid_len == 7 || uid_len == 10)) {
        return false;
    }

    this->type = t;
    this->size = uid_len;
    std::memset(this->uid, 0x00, sizeof(this->uid));
    std::memcpy(this->uid, uid, uid_len);
    this->atqa   = emulation_settings[m5::stl::to_underlying(t)].atqa;
    this->sak    = emulation_settings[m5::stl::to_underlying(t)].sak;
    this->blocks = get_number_of_blocks(t);

    return valid();
}

}  // namespace a
}  // namespace nfc
}  // namespace m5
