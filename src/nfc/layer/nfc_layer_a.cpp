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

bool NFCLayerA::request(uint16_t& atqa)
{
    return _impl->request(atqa);
}

bool NFCLayerA::wakeup(uint16_t& atqa)
{
    return _impl->wakeup(atqa);
}

bool NFCLayerA::detect(std::vector<UID>& devs, const uint32_t timeout_ms)
{
    devs.clear();

    auto timeout_at = m5::utility::millis() + timeout_ms;
    UID uid{};

    uint16_t atqa{};
    do {
        // Exists devices?
        if (!request(atqa)) {
            break;
        }

        // Select
        if (!select(uid)) {
            return false;
        }
        // Type identification
        uid.type   = identify_type(uid);
        uid.blocks = get_number_of_blocks(uid.type);
        _activeUID = uid;

        M5_LIB_LOGD("Detect:%s", uid.uidAsString().c_str());

        // Hlt
        if (!deactivate()) {
            M5_LIB_LOGD("Failed to deactivate");
            return false;
        }

        // Append valid UID
        push_back_uid(devs, uid);

    } while (m5::utility::millis() <= timeout_at);

    return !devs.empty();
}

bool NFCLayerA::select(m5::nfc::a::UID& uid)
{
    return _impl->select(uid);
}

bool NFCLayerA::activate(const UID& uid)
{
    return _impl->activate(uid);
}

bool NFCLayerA::deactivate()
{
    return _impl->deactivate();
}

Type NFCLayerA::identify_type(const UID& uid)
{
    const uint8_t sak = uid.sak;

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
            // RATS?
            if (true) {
                return Type::MIFARE_Classic_4K;  // 0x18
            }
            // PlusEV1, PlusS, PlusX (SL1)
            return Type::Unknown;
        }
        // Bit 5 No
        if (sak & 0x01 /*b1*/) {
            // MIFARE Mini
            return Type::Unknown;  // 0x09
        }
        if (sak & 0x20 /*b6*/) {
            return Type::MIFARE_Classic_1K;  // 0x28 SmartMX with
        }
        // RATS?
        if (true) {
            return Type::MIFARE_Classic_1K;  // 0x08
        }
        // PlusEV1, PlusS, PlusX, PlusSE 1K (SL1)
        return Type::Unknown;
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
        return Type::ISO_14443_4;
    }
    // Bit 6 No
    uint8_t ver[16]{};
    if (!ntag_get_version(ver)) {
        // UltraLight or UltraLightC or NTAG203
        uint8_t des[] = {m5::stl::to_underlying(Command::AUTHENTICATE_1), 0x00};
        uint8_t rbuf[16]{};
        uint16_t rx_len = sizeof(rbuf);
        if (nfca_transceive(rbuf, rx_len, des, sizeof(des), TIMEOUT_3DES)) {
            if (rbuf[0] == 0xAF) {
                return Type::MIFARE_UltraLightC;
            }
        }
#if 1
        // Re-activate if transceive has been failed (PICC goes into IDLE mode)
        return activate(uid) ? Type::MIFARE_UltraLight : Type::Unknown;
#else
        // TODO : NTAG203
        return Type::MIFARE_UltraLight;
#endif
    }

    if (ver[0] != 0x00 || ver[1] != 0x04 /*NXP*/ || ver[7] != 0x03 /* ISO14443-A*/) {
        return Type::Unknown;
    }
    if (ver[2] == 0x04 /* NXP */) {
        // ver[6] Storage size code
        return (ver[6] == 0x0E)   ? Type::NTAG_212
               : (ver[6] == 0x0F) ? Type::NTAG_213
               : (ver[6] == 0x11) ? Type::NTAG_215
               : (ver[6] == 0x13) ? Type::NTAG_216
               : (ver[6] == 0x0B) ? ((ver[4] == 0x02) ? Type::NTAG_210u : Type::NTAG_210)
                                  : Type::Unknown;
    }
    if (ver[2] == 0x03 /*UltraLight */) {
        // UltraLight EV1, Nano
        return Type::Unknown;
    }
    return Type::Unknown;
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)
{
    return _activeUID.valid() && (_activeUID.isMifareClassic() ? _impl->mifare_classic_read_block(rx, rx_len, addr)
                                                               : _impl->nfca_read_block(rx, rx_len, addr));
}

bool NFCLayerA::write(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    bool can = safety ? is_user_block(activatedDevice().type, addr) : true;
    if (safety && !can) {
        M5_LIB_LOGW("%s %u This is NOT user area", activatedDevice().typeAsString().c_str(), addr);
    }
    return (can && _activeUID.valid())
               ? (_activeUID.isMifareClassic() ? _impl->mifare_classic_write_block(addr, tx, tx_len)
                                               : _impl->nfca_write_block(addr, tx, tx_len))
               : false;
}

bool NFCLayerA::dump(const m5::nfc::a::mifare::Key& mkey)
{
    if (_activeUID.valid()) {
        if (_activeUID.isMifareClassic()) {
            return dump_sector_structure(_activeUID, mkey);
        } else if (_activeUID.supportsNFC()) {
            return dump_page_structure(_activeUID.blocks);
        }
        M5_LIB_LOGW("Not supported %s", _activeUID.typeAsString().c_str());
    }
    return false;
}

bool NFCLayerA::dump(const uint8_t block)
{
    if (_activeUID.valid()) {
        if (_activeUID.isMifareClassic()) {
            return dump_sector(get_sector(block));
        } else if (_activeUID.supportsNFC()) {
            return dump_page(block);
        }
        M5_LIB_LOGW("Not supported %s", _activeUID.typeAsString().c_str());
    }
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

    for (int_fast8_t sector = 0; sector < sectors; ++sector) {
        auto sblock = get_sector_trailer_block_from_sector(sector);
        if (mifareClassicAuthenticateA(uid, sblock, key)) {
            if (!dump_sector(sector)) {
                M5_LIB_LOGE("Failed to dump:%u", sector);
                return false;
            }
        } else {
            M5_LIB_LOGE("Failed to AUTH %u", sblock);
            return false;
        }
    }
    return true;
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
    if (!read(sbuf, slen, saddr) || slen != 16) {
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
        if (!read(dbuf, dlen, daddr) || dlen != 16) {
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

    if (read(buf, blen, baddr)) {
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

bool NFCLayerA::push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid)
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

bool NFCLayerA::nfca_transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                const uint32_t timeout_ms)
{
    return _impl->nfca_transceive(rx, rx_len, tx, tx_len, timeout_ms);
}

bool NFCLayerA::mifareClassicAuthenticateA(const m5::nfc::a::UID& uid, const uint8_t block,
                                           const m5::nfc::a::mifare::Key& key)
{
    return _impl->mifare_classic_authenticate(true, uid, block, key);
}

bool NFCLayerA::mifareClassicAuthenticateB(const m5::nfc::a::UID& uid, const uint8_t block,
                                           const m5::nfc::a::mifare::Key& key)
{
    return _impl->mifare_classic_authenticate(false, uid, block, key);
}

bool NFCLayerA::ntag_get_version(uint8_t info[10])
{
    return _impl->ntag_get_version(info);
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
