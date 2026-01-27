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
#include <mbedtls/des.h>
#include <algorithm>

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

constexpr uint8_t zero_all[8]{};
constexpr uint8_t ff_all[8]{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

std::string to_string(const uint8_t* p, const uint8_t size)
{
    if (size > m5::nfc::f::FELICA_ID_LENGTH) {
        return std::string{};
    }
    char buf[2 * m5::nfc::f::FELICA_ID_LENGTH + 1]{};
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

bool make_session_key(uint8_t sk[16], const uint8_t ck[16], const uint8_t rc[16])
{
    using m5::utility::crypto::TripleDES;
    using Key16 = TripleDES::Key16;

    // 1) (CK[7..0] reversed + CK[15..8] reversed)
    Key16 key{};
    for (int i = 0; i < 8; ++i) {
        key[i]     = ck[7 - i];   // CK1 reversed
        key[8 + i] = ck[15 - i];  // CK2 reversed
    }

    // 2)  (RC[7..0] reversed + RC[15..8] reversed)
    uint8_t data[16]{};
    for (int i = 0; i < 8; ++i) {
        data[i]     = rc[7 - i];   // RC1 reversed
        data[8 + i] = rc[15 - i];  // RC2 reversed
    }

    // 3) 2-key 3DES CBC(IV=0)
    TripleDES des(TripleDES::Mode::CBC, TripleDES::Padding::None);

    uint8_t tmp[16]{};
    if (des.encrypt(tmp, data, sizeof(data), key) != 16) {
        return false;
    }

    // 4) expand
    //    SK1 = reverse(tmp[0..7])
    //    SK2 = reverse(tmp[8..15])
    for (int i = 0; i < 8; ++i) {
        sk[i]     = tmp[7 - i];   // SK1
        sk[8 + i] = tmp[15 - i];  // SK2
    }

    return true;
}

bool generate_mac(uint8_t mac[8], const uint8_t* plain, uint32_t plain_len, const uint8_t* block_data,
                  uint32_t block_len, const uint8_t sk1[8], const uint8_t sk2[8], const uint8_t rc[16])
{
    using m5::utility::crypto::TripleDES;

    if (!mac || !block_data || !block_len || !sk1 || !sk2 || !rc) {
        return false;
    }

    // key1[::-1] + key2[::-1]
    TripleDES::Key16 key{};
    for (int i = 0; i < 8; ++i) {
        key[i]     = sk1[7 - i];
        key[8 + i] = sk2[7 - i];
    }

    // IV = RC1[7..0] (first 8byte in RC)
    uint8_t iv[8]{};
    for (int i = 0; i < 8; ++i) {
        iv[i] = rc[7 - i];
    }

    TripleDES des(TripleDES::Mode::CBC, TripleDES::Padding::None, iv);

    // plain[::-1] + concat(each 8byte chunk reversed)
    std::vector<uint8_t> buf;
    buf.reserve(((plain_len + block_len) + 7) & ~7u);

    // plain[::-1]
    if (plain && plain_len) {
        for (uint32_t i = 0; i < plain_len; ++i) {
            buf.push_back(plain[plain_len - 1 - i]);
        }
    }

    // block_data[i:i+8][::-1]
    for (uint32_t off = 0; off < block_len; off += 8) {
        uint32_t chunk = std::min<uint32_t>(8, block_len - off);
        uint8_t tmp[8]{};
        std::memcpy(tmp, block_data + off, chunk);
        for (uint32_t i = 0; i < 8; ++i) {
            buf.push_back(tmp[7 - i]);
        }
    }

    std::vector<uint8_t> out(buf.size());
    auto len = des.encrypt(out.data(), buf.data(), static_cast<uint32_t>(buf.size()), key);
    if (len != buf.size()) {
        return false;
    }

    for (int i = 0; i < 8; ++i) {
        mac[i] = out[out.size() - 1 - i];
    }
    return true;
}

bool is_read_only_lite(const block_t block)
{
    return block == lite::MAC || block == lite::SYS_C;
}

bool is_read_only_lite_s(const block_t block)
{
    return block == lite_s::MAC || block == lite_s::D_ID || block == lite_s::SYS_C || block == lite_s::WCNT ||
           block == lite_s::CRC_CHECK;
}

bool can_read_lite(const block_t block)
{
    return !(block == lite_s::RC || block == lite_s::CK);
}

bool can_read_lite_s(const block_t block)
{
    return !(block == lite_s::RC || block == lite_s::CK);
}

//
bool PICC::valid() const
{
    return type != Type::Unknown &&  //
           memcmp(idm, zero_all, 8) && memcmp(idm, ff_all, 8) && memcmp(pmm, zero_all, 8) && memcmp(pmm, ff_all, 8) &&
           ((type == Type::FeliCaLite || type == Type::FeliCaLiteS) ? get_user_area_size(type) : true) && format;
}

bool PICC::validEmulation() const
{
    // Currently only Lite-S
    return (type == Type::FeliCaLiteS) && valid() && emulation_sc == 0x88B4;
}

std::string PICC::idmAsString() const
{
    return to_string(idm, sizeof(idm));
}

std::string PICC::pmmAsString() const
{
    return to_string(pmm, sizeof(pmm));
}

std::string PICC::typeAsString() const
{
    const auto idx = m5::stl::to_underlying(this->type);
    return std::string((idx <= m5::stl::size(name_table)) ? name_table[idx] : name_unknown);
}

bool PICC::emulate(const Type t, const uint8_t idm[FELICA_ID_LENGTH], const uint8_t pmm[FELICA_ID_LENGTH],
                   const uint16_t sc /*Options for the future*/)
{
    (void)sc;
    if (t != Type::FeliCaLiteS || !idm || !pmm) {
        return false;
    }

    this->type = t;
    memcpy(this->idm, idm, sizeof(this->idm));
    memcpy(this->pmm, pmm, sizeof(this->pmm));
    this->emulation_sc = 0x88B4;  // Base system code
    this->format       = format_lite;

    return validEmulation();
}

bool operator==(const PICC& a, const PICC& b)
{
    return a.valid() && b.valid() && memcmp(a.idm, b.idm, sizeof(a.idm)) == 0 &&
           memcmp(a.pmm, b.pmm, sizeof(a.pmm)) == 0 && a.type == b.type;
}

}  // namespace f
}  // namespace nfc
}  // namespace m5
