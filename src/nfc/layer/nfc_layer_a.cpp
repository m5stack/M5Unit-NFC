/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.hpp
  @brief Common layer for NFC-A Related Units
*/
#include "nfc_layer_a.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>

using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
void dump_block(const uint8_t* buf, const int16_t block = -1, const int16_t sector = -1, const uint8_t ab = 0xFF,
                const bool aberror = false, const bool valueblock = false)
{
    char tmp[128 + 1] = "   ";
    uint32_t left{};
    // Sector
    if (sector >= 0) {
        left = snprintf(tmp, 4, "%02d)", sector);
    } else {
        left = 3;
    }
    // Block
    if (block >= 0) {
        left += snprintf(tmp + left, 7, "[%03d]:", block);
    } else {
        strcat(tmp, "      ");
        left += 6;
    }
    // Data
    for (uint8_t i = 0; i < 16; ++i) {
        left += snprintf(tmp + left, 4, "%02X ", buf[i]);
    }
    // Access bits
    if (ab != 0xFF) {
        if (!aberror) {
            left += snprintf(tmp + left, 8, "[%d %d %d]", (ab >> 2) & 1, (ab >> 1) & 1, (ab & 1));
        } else {
            strcat(tmp + left, "[ERROR]");
            left += 7;
        }
    }
    if (valueblock) {
        int32_t value{};
        uint8_t addr{};
        if (decode_value_block(value, addr, buf)) {
            snprintf(tmp + left, 26, " Addr:%03u Val:%" PRId32 "", addr, value);  // PRId32 for compile on NanoC6
        } else {
            strcat(tmp + left, "[Illgal value blcok]");
        }
    }
    ::puts(tmp);
}
}  // namespace

namespace m5 {
namespace unit {
namespace nfc {

// API
const m5::nfc::a::UID& NFCLayerA::activatedDevice() const
{
    return _impl->activatedDevice();
}

bool NFCLayerA::detect(std::vector<UID>& devices, const uint32_t timeout_ms)
{
    return _impl->detect(devices, timeout_ms);
}

bool NFCLayerA::activate(const UID& uid)
{
    return _impl->activate(uid);
}

bool NFCLayerA::deactivate()
{
    return _impl->deactivate();
}

bool NFCLayerA::mifare_authenticate(const m5::nfc::a::Command cmd, const UID& uid, const uint8_t block, const Key& key)
{
    return _impl->mifare_authenticate(cmd, uid, block, key);
}

bool NFCLayerA::readBlock(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)
{
    return _impl->readBlock(rx, rx_len, addr);
}

bool NFCLayerA::writeBlock(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    bool can = safety ? is_user_block(activatedDevice().type, addr) : true;
    if (safety && !can) {
        M5_LIB_LOGW("%s %u This is NOT user area", activatedDevice().typeAsString().c_str(), addr);
    }
    return can ? _impl->writeBlock(addr, tx, tx_len) : false;
}

bool NFCLayerA::dump(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::Key& mkey)
{
    if (uid.isClassic()) {
        return dump_sector_structure(uid, mkey);
    } else if (uid.supportsNFC()) {
        return dump_page_structure(uid.blocks);
    }
    M5_LIB_LOGW("Not supported %s", uid.typeAsString().c_str());
    return false;
}

bool NFCLayerA::dump(const m5::nfc::a::UID& uid, const uint8_t block)
{
    if (uid.isClassic()) {
        return dump_sector(get_sector(block));
    } else if (uid.supportsNFC()) {
        return dump_page(block);
    }
    M5_LIB_LOGW("Not supported %s", uid.typeAsString().c_str());
    return false;
}

bool NFCLayerA::dump_sector_structure(const UID& uid, const Key& key)
{
    uint8_t sectors = get_number_of_sectors(uid.type);
    if (!sectors) {
        return false;
    }

    puts(
        "Sec[Blk]:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F [Access]\n"
        "-----------------------------------------------------------------");

    bool res{};
    for (int_fast8_t sector = 0; sector < sectors; ++sector) {
        auto sblock = get_sector_trailer_block_from_sector(sector);
        if (mifareAuthenticateA(uid, sblock, key)) {
            if (!dump_sector(sector)) {
                M5_LIB_LOGE(">>>> Failed to dump:%u", sector);
                return false;
            }
        } else {
            M5_LIB_LOGE(">>>>Failed to AUTH %u", sblock);
            return false;
        }
    }
    return res;
}

bool NFCLayerA::dump_sector(const uint8_t sector)
{
    // Sector 0~31 has 4 blocks, 32-39 has 16 blocks (4K)
    const uint8_t blocks = (sector < 32) ? 4U : 16U;
    const uint8_t base   = (sector < 32) ? sector * blocks : 128U + (sector - 32) * blocks;

    uint8_t sbuf[16]{};
    uint16_t slen{16};
    uint8_t permissions[4]{};                 // [3] is sector trailer
    const uint8_t saddr = base + blocks - 1;  //  sector traler

    // Read sector trailer
    if (!readBlock(sbuf, slen, saddr) || slen != 16) {
        return false;
    }

    bool error = !decode_access_bits(permissions, sbuf + 6 /* Access bits offset */);
    //    M5_LIB_LOGW(">> S:%u => %u [%u,%u,%u,%u]", sector, saddr, permissions[0], permissions[1], permissions[2],
    //                permissions[3]);

    // Data
    for (int_fast8_t i = 0; i < blocks - 1; ++i) {
        uint8_t dbuf[16]{};
        uint16_t dlen{16};
        uint8_t daddr = base + i;
        if (!readBlock(dbuf, dlen, daddr) || dlen != 16) {
            return false;
        }
        const uint8_t poffset      = (blocks == 4) ? i : i / 5;
        const uint8_t permission   = permissions[poffset];
        const bool show_permission = (blocks == 4) ? true : (i % 5) == 0;
        dump_block(dbuf, base + i, (i == 0) ? sector : -1, show_permission ? permission : 0xFF, error,
                   is_value_block_permission(permission));
    }
    // Sector trailer
    dump_block(sbuf, saddr, -1, permissions[3], error);

    return true;
}

bool NFCLayerA::dump_page_structure(const uint8_t maxPage)
{
    puts(
        "Page    :00 01 02 03\n"
        "--------------------");

    for (uint_fast8_t page = 0; page < maxPage; page += 4) {
        if (!dump_page(page)) {
            return false;
        }
    }
    return true;
}

bool NFCLayerA::dump_page(const uint8_t page)
{
    uint8_t buf[16]{};
    uint16_t blen{16};
    uint8_t baddr = page & ~0x03;

    if (readBlock(buf, blen, baddr)) {
        for (int_fast8_t off = 0; off < 4; ++off) {
            auto idx = off << 2;
            printf("[%03d/%02X]:%02X %02X %02X %02X\n", baddr + off, baddr + off, buf[idx + 0], buf[idx + 1],
                   buf[idx + 2], buf[idx + 3]);
        }

        return true;
    }
    for (int_fast8_t off = 0; off < 4; ++off) {
        printf("[%3d/%02X] ERROR\n", baddr + off, baddr + off);
    }
    return false;
}

bool NFCLayerA::Adapter::push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid)
{
    // Keep unique valid UID
    // std::set cannot use for it, Cannot UID < UID
    auto it =
        std::find_if(v.begin(), v.end(), [&uid](const UID& u) { return std::memcmp(u.uid, uid.uid, uid.size) == 0; });
    // New uid
    if (it == v.end()) {
        v.push_back(uid);
        return true;
    }
    // Overwrite?
    if (!it->valid() && uid.valid()) {
        *it = uid;
        return true;
    }
    return false;
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
