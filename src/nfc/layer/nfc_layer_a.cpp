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
        _activeUID = uid;

        M5_LIB_LOGE("Detect:%s", uid.uidAsString().c_str());

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

bool NFCLayerA::read4(uint8_t rx[4], const uint8_t addr)
{
    uint16_t rx_len{4};
    return rx && _activeUID.valid() &&
           (_activeUID.canFastRead() ? (_impl->ntag_read_page(rx, rx_len, addr, addr) && rx_len == 4)
                                     : _impl->nfca_read_block(rx, addr));
}

bool NFCLayerA::read16(uint8_t rx[16], const uint8_t addr)
{
#if 1
    uint16_t rx_len{16};
    return rx && _activeUID.valid() &&
           (_activeUID.canFastRead() ? (_impl->ntag_read_page(rx, rx_len, addr, addr + 3) && rx_len == 16)
                                     : _impl->nfca_read_block(rx, addr));
#else
    // AN13089 3.1.2 Only in case of 4 pages reading the READ command is faster than the FAST_READ.
    return rx && _activeUID.valid() && _impl->nfca_read_block(rx, addr);
#endif
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t addr, const m5::nfc::a::mifare::classic::Key& key)
{
    if (!rx || !rx_len || !_activeUID.valid()) {
        return false;
    }
    return _activeUID.canFastRead() ? read_using_fast(rx, rx_len, addr) : read_using_read16(rx, rx_len, addr, key);
}

bool NFCLayerA::read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    const Type t = _activeUID.type;
    //    const uint16_t fifo_depth = _impl->max_fifo_depth(); // ST25R3916 512 but cannot return long length...
    const uint16_t fifo_depth = 64 + 2 /* CRC */;
    const uint16_t last       = get_last_user_block(t);
    uint16_t need_page        = ((rx_len + 3) >> 2);
    uint16_t from             = std::min<uint16_t>(last, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to               = std::min<uint16_t>(from + need_page - 1, last);
    uint16_t pages            = to - from + 1;

    uint16_t read_size = pages << 2;  // 4 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGE("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
        rx_len = 0;
        return false;
    }

    M5_LIB_LOGD("READ:%u-%u %u %u", from, to, pages, pages << 2);

    uint16_t actual{};
    uint16_t batch_pages = std::min<uint16_t>((fifo_depth - 2) >> 2, pages);
    uint16_t spage       = from;
    uint16_t epage       = from + batch_pages - 1;
    rx_len               = 0;

    while (actual < pages && spage <= to) {
        if (epage > to) {
            epage = to;
        }
        uint16_t ps  = epage - spage + 1;
        uint16_t len = ps << 2;

        M5_LIB_LOGD("  READ:%u-%u %u %u/%u", spage, epage, len, actual, pages);

        if (!_impl->ntag_read_page(rx + rx_len, len, spage, epage) || len != (ps << 2)) {
            M5_LIB_LOGE("Failed to read %u-%u", spage, epage);
            return false;
        }
        rx_len += len;
        actual += ps;
        spage += ps;
        epage += ps;
    }
    return true;
}

bool NFCLayerA::read_using_read16(uint8_t* rx, uint16_t& rx_len, const uint8_t addr,
                                  const m5::nfc::a::mifare::classic::Key& key)
{
    const Type t        = _activeUID.type;
    uint16_t need_block = ((rx_len + 15) >> 4);
    uint16_t last       = get_last_user_block(_activeUID.type);
    uint16_t from       = std::min<uint16_t>(last, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to         = std::min<uint16_t>(from + need_block - 1, last);
    uint16_t blocks     = to - from + 1;

    uint16_t read_size = blocks << 4;  // 16 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGE("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
        rx_len = 0;
        return false;
    }

    rx_len         = 0;
    uint8_t sector = get_sector(from);
    if (_activeUID.isMifareClassic()) {
        M5_LIB_LOGD("AUTH:%u", sector);
        if (!mifareClassicAuthenticateA(_activeUID, get_sector_trailer_block_from_sector(sector), key)) {
            M5_LIB_LOGE("Failed AUTH sec:%u", sector);
            return false;
        }
    }

    uint16_t actual{};
    uint16_t cur = from;
    uint16_t add = _activeUID.isMifareClassic() ? 1 : 4 /* 4 pages */;

    M5_LIB_LOGD("READ:blocks:%u-%u %u %u (%u)", from, to, blocks, _activeUID.blocks, add);

    while (actual < blocks && cur <= last) {
        uint8_t sec = get_sector(cur);
        if (sec != sector) {
            sector = sec;
            if (_activeUID.isMifareClassic()) {
                M5_LIB_LOGD("   AUTH:%u/%u", cur, sec);
                if (!mifareClassicAuthenticateA(_activeUID, get_sector_trailer_block_from_sector(sector), key)) {
                    M5_LIB_LOGE("Failed to AUTH sec:%u", sector);
                    return false;
                }
            }
        }
        if (!is_user_block(_activeUID.type, cur)) {
            ++cur;
            continue;
        }
        M5_LIB_LOGD("   READ:%u %u/%u", cur, actual, blocks);
        if (!read16(rx + 16 * actual, cur)) {
            M5_LIB_LOGE("Failed to read block:%u", cur);
            return false;
        }
        rx_len += 16;
        cur += add;
        ++actual;
    }
    return true;
}

bool NFCLayerA::write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    if (!tx || !tx_len || !_activeUID.valid()) {
        return false;
    }

    if (safety && !is_user_block(_activeUID.type, addr)) {
        M5_LIB_LOGW("Write has been rejected due to safety %u", addr);
        return false;
    }

    uint8_t buf[4]{};
    memcpy(buf, tx, std::min<uint16_t>(4, tx_len));
    return _impl->nfca_write_page(addr, buf);
}

bool NFCLayerA::write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    if (!tx || !tx_len || !_activeUID.valid()) {
        return false;
    }

    uint8_t buf[16]{};
    memcpy(buf, tx, std::min<uint16_t>(16, tx_len));

    //
    if (_activeUID.supportsNFC()) {
        uint8_t epage = addr + 4 - 1;
        if (safety && (!is_user_block(_activeUID.type, addr) || !is_user_block(_activeUID.type, epage))) {
            M5_LIB_LOGW("Write has been rejected due to safety %u-%u", addr, epage);
            return false;
        }
        for (uint_fast8_t i = 0; i < 4; ++i) {
            if (!_impl->nfca_write_page(addr + i, buf + i * 4)) {
                return false;
            }
        }
        return true;
    }

    //
    if (safety && !is_user_block(_activeUID.type, addr)) {
        M5_LIB_LOGW("Write has been rejected due to safety %u", addr);
        return false;
    }
    return _impl->nfca_write_block(addr, buf);
}

bool NFCLayerA::write(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                      const m5::nfc::a::mifare::classic::Key& key)
{
    if (!tx || !tx_len || !_activeUID.valid()) {
        return false;
    }
    return _activeUID.supportsNFC() ? write_using_write4(addr, tx, tx_len) : write_using_write16(addr, tx, tx_len, key);
}

bool NFCLayerA::write_using_write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len)
{
    const Type t         = _activeUID.type;
    const uint16_t last  = get_last_user_block(t);
    uint16_t need_page   = ((tx_len + 3) >> 2);
    uint16_t from        = std::min<uint16_t>(_activeUID.blocks - 1, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to          = std::min<uint16_t>(from + need_page - 1, last);
    uint16_t pages       = to - from + 1;
    const uint16_t total = pages << 2;  // 4 byte unit
    uint16_t written{0};

    if (!is_user_block(t, from)) {
        M5_LIB_LOGE("The write start position is not in the user area %u/%u", addr, from);
        return false;
    }

    if (tx_len > total) {
        M5_LIB_LOGE("Not enough user area from %u-%u %u/%u", from, to, tx_len, total);
        return false;
    }

    M5_LIB_LOGD("WRITE:%u,%u %u-%u %u %u", addr, tx_len, from, to, pages, total);

    uint8_t cur         = from;
    const uint8_t* data = tx;
    while (written < total) {
        uint16_t sz = std::min<uint16_t>(4, total - written);
        M5_LIB_LOGD("  WRITE:%u %u %u/%u", cur, sz, written, total);
        if (!write4(cur, data, sz)) {
            break;
        }
        written += sz;
        data += sz;
        ++cur;
    }
    return written == total;
}

bool NFCLayerA::write_using_write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                                    const m5::nfc::a::mifare::classic::Key& key)
{
    const Type t    = _activeUID.type;
    auto last       = get_last_user_block(t);
    uint16_t blocks = (tx_len + 15) >> 4;
    uint16_t b{};
    while (b < blocks) {
        if (addr + b > last) {
            M5_LIB_LOGW("Write has been rejected out of user block range %u-%u", addr, addr + blocks - 1);
            return false;
        }
        b += (1 + !is_user_block(t, addr + b));  //  Skip sector trailer
    }

    uint16_t written{0};
    uint8_t cur         = addr;
    const uint8_t* data = tx;

    M5_LIB_LOGD("WRITE:%u,%u %u- %u", addr, tx_len, cur, blocks);

    uint8_t sector = get_sector(cur);
    if (_activeUID.isMifareClassic()) {
        M5_LIB_LOGD("AUTH:%u", sector);
        if (!mifareClassicAuthenticateA(_activeUID, get_sector_trailer_block_from_sector(sector), key)) {
            M5_LIB_LOGE("Failed AUTH sec:%u", sector);
            return false;
        }
    }

    while (written < tx_len) {
        uint8_t sec = get_sector(cur);
        if (sec != sector) {
            sector = sec;
            if (_activeUID.isMifareClassic()) {
                M5_LIB_LOGD("  AUTH:%u", sector);
                if (!mifareClassicAuthenticateA(_activeUID, get_sector_trailer_block_from_sector(sector), key)) {
                    M5_LIB_LOGE("Failed to AUTH sec:%u", sector);
                    break;
                }
            }
        }
        if (!is_user_block(t, cur)) {
            ++cur;
            continue;
        }

        uint16_t sz = std::min<uint16_t>(16, tx_len - written);
        M5_LIB_LOGD("  WRITE:%u %u %u/%u", cur, sz, written, tx_len);
        if (!write16(cur, data, sz)) {
            break;
        }
        written += sz;
        data += sz;
        ++cur;
    }
    return written == tx_len;
}

bool NFCLayerA::dump(const Key& mkey)
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
            return dump_page(block, _activeUID.blocks);
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
    uint8_t permissions[4]{};                 // [3] is sector trailer
    const uint8_t saddr = base + blocks - 1;  //  sector traler

    // Read sector trailer
    if (!read16(sbuf, saddr)) {
        return false;
    }

    bool error = !decode_access_bits(permissions, sbuf + 6 /* Access bits offset */);
    //    M5_LIB_LOGW(">> S:%u => %u [%u,%u,%u,%u]", sector, saddr, permissions[0], permissions[1], permissions[2],
    //                permissions[3]);

    // Data
    for (int_fast8_t i = 0; i < blocks - 1; ++i) {
        uint8_t dbuf[16]{};
        uint8_t daddr = base + i;
        if (!read16(dbuf, daddr)) {
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

bool NFCLayerA::dump_page_structure(const uint16_t maxPage)
{
    puts(
        "Page    :00 01 02 03\n"
        "--------------------");

    for (uint_fast8_t page = 0; page < maxPage; page += 4) {
        if (!dump_page(page, maxPage)) {
            return false;
        }
    }
    return true;
}

bool NFCLayerA::dump_page(const uint8_t page, uint16_t maxPage)
{
    uint8_t buf[16]{};
    uint16_t from  = page;
    uint16_t pages = std::min<uint16_t>(4, maxPage - from);
    // uint16_t to     = page + pages - 1;
    // uint16_t rx_len = pages * 4;

    bool ok{true};
    if (pages == 4) {  // Ultralight, NTAG
        ok = read16(buf, from);
    } else {
        // The number of pages in an NTAG is not necessarily a multiple of 4
        for (uint_fast8_t i = 0; i < pages; ++i) {
            ok &= read4(buf + (i << 2), from + i);
        }
    }
    if (ok) {
        for (uint_fast8_t off = 0; off < pages; ++off) {
            auto idx = off << 2;
            printf("[%03d/%02X]:%02X %02X %02X %02X\n", from + off, from + off, buf[idx + 0], buf[idx + 1],
                   buf[idx + 2], buf[idx + 3]);
        }
        return true;
    }

    for (uint_fast8_t off = 0; off < pages; ++off) {
        printf("[%3d/%02X] ERROR\n", from + off, from + off);
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

bool NFCLayerA::mifareClassicAuthenticateA(const m5::nfc::a::UID& uid, const uint8_t block,
                                           const m5::nfc::a::mifare::classic::Key& key)
{
    return _impl->mifare_classic_authenticate(true, uid, block, key);
}

bool NFCLayerA::mifareClassicAuthenticateB(const m5::nfc::a::UID& uid, const uint8_t block,
                                           const m5::nfc::a::mifare::classic::Key& key)
{
    return _impl->mifare_classic_authenticate(false, uid, block, key);
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
