/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.cpp
  @brief Common layer for NFC-A related units
*/
#include "nfc_layer_a.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>

using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;
using namespace m5::nfc::ndef;

namespace {

void dump_block(const uint8_t buf[16], const int16_t block = -1, const int16_t sector = -1, const uint8_t ab = 0xFF,
                const bool aberror = false, const bool value_block = false)
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

    // Value block
    int32_t value{};
    uint8_t addr{};
    if (value_block && decode_value_block(value, addr, buf)) {
        snprintf(tmp + left, 26, " V:%" PRId32 " A:%3u", value, addr);  // PRId32 for compile on NanoC6
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

bool NFCLayerA::detect(PICC& picc, const uint32_t timeout_ms)
{
    std::vector<PICC> piccs;
    if (detect(piccs, timeout_ms)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

bool NFCLayerA::detect(std::vector<PICC>& piccs, const uint32_t timeout_ms)
{
    piccs.clear();

    auto timeout_at = m5::utility::millis() + timeout_ms;
    PICC picc{};

    uint16_t atqa{};
    do {
        // Exists PICC?
        if (!request(atqa)) {
            break;
        }

        // Select
        if (!select(picc)) {
            return false;
        }
        M5_LIB_LOGD("Detect:%s %s", picc.uidAsString().c_str(), picc.typeAsString().c_str());

        // Hlt
        if (!deactivate()) {
            M5_LIB_LOGD("Failed to deactivate");
            return false;
        }

        // Append valid PICC
        push_back_picc(piccs, picc);

    } while (m5::utility::millis() <= timeout_at);

    return !piccs.empty();
}

bool NFCLayerA::select(m5::nfc::a::PICC& picc)
{
    _activePICC.clear();
    if (_impl->select(picc)) {
        _activePICC = picc;
        return true;
    }
    return false;
}

bool NFCLayerA::activate(const PICC& picc)
{
    _activePICC.clear();  // (*1)
    if (_impl->activate(picc)) {
        _activePICC = picc;
        return true;
    }
    return false;
}

bool NFCLayerA::reactivate(const PICC& picc)
{
    // If arg referrence is the same as _activePICC, it will cause an error, so it must be a separate instance (*1)
    PICC tmp = picc;
    uint16_t discard{};
    return tmp.valid() && deactivate() && wakeup(discard) && activate(tmp);
}

bool NFCLayerA::deactivate()
{
    _activePICC.clear();
    return _impl->deactivate();
}

bool NFCLayerA::read4(uint8_t rx[4], const uint8_t addr)
{
    uint16_t rx_len{4};
    return rx && _activePICC.valid() &&
           (_activePICC.canFastRead() ? (_impl->ntag_read_page(rx, rx_len, addr, addr) && rx_len == 4)
                                      : _impl->nfca_read_block(rx, addr));
}

bool NFCLayerA::read16(uint8_t rx[16], const uint8_t addr)
{
#if 1
    uint16_t rx_len{16};
    return rx && _activePICC.valid() &&
           (_activePICC.canFastRead() ? (_impl->ntag_read_page(rx, rx_len, addr, addr + 3) && rx_len == 16)
                                      : _impl->nfca_read_block(rx, addr));
#else
    // AN13089 3.1.2 Only in case of 4 pages reading the READ command is faster than the FAST_READ.
    return rx && _activePICC.valid() && _impl->nfca_read_block(rx, addr);
#endif
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t addr, const m5::nfc::a::mifare::classic::Key& key)
{
    if (!rx || !rx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.canFastRead() ? read_using_fast(rx, rx_len, addr) : read_using_read16(rx, rx_len, addr, key);
}

bool NFCLayerA::read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    const Type t = _activePICC.type;
    // ST25R3916 512 but cannot use long length...why?
    uint16_t fifo_depth = std::min<uint16_t>(_impl->max_fifo_depth(), 64);

    const uint16_t last = get_last_user_block(t);
    uint16_t need_page  = ((rx_len + 3) >> 2);
    uint16_t from       = std::min<uint16_t>(last, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to         = std::min<uint16_t>(from + need_page - 1, last);
    uint16_t pages      = to - from + 1;

    uint16_t read_size = pages << 2;  // 4 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGE("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
        rx_len = 0;
        return false;
    }

    uint16_t actual{};
    uint16_t batch_pages = std::min<uint16_t>((fifo_depth - 2 /*CRC*/) >> 2, pages);
    uint16_t spage       = from;
    uint16_t epage       = from + batch_pages - 1;
    rx_len               = 0;

    M5_LIB_LOGD("READ:%u-%u %u %u %u", from, to, pages, pages << 2, batch_pages);

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
    const Type t        = _activePICC.type;
    uint16_t need_block = ((rx_len + 15) >> 4);
    uint16_t last       = get_last_user_block(_activePICC.type);
    uint16_t from       = std::min<uint16_t>(last, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to         = std::min<uint16_t>(from + need_block - 1, last);
    uint16_t blocks     = to - from + 1;

    uint16_t read_size = blocks << 4;  // 16 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGE("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
        rx_len = 0;
        return false;
    }

    rx_len = 0;
    uint16_t st_block{};
    uint16_t actual{};
    uint16_t cur = from;
    uint16_t add = _activePICC.isMifareClassic() ? 1 : 4 /* 4 pages */;

    M5_LIB_LOGD("READ:blocks:%u-%u %u %u (%u)", from, to, blocks, _activePICC.blocks, add);

    while (actual < blocks && cur <= last) {
        uint16_t stb = get_sector_trailer_block(cur);
        if (stb != st_block) {
            st_block = stb;
            if (_activePICC.isMifareClassic()) {
                M5_LIB_LOGD("   AUTH:%u/%u", cur, st_block);
                if (!mifareClassicAuthenticateA(st_block, key)) {
                    M5_LIB_LOGE("Failed to AUTH %u", st_block);
                    return false;
                }
            }
        }
        if (!is_user_block(_activePICC.type, cur)) {
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
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }

    if (safety && !is_user_block(_activePICC.type, addr)) {
        M5_LIB_LOGW("Write has been rejected due to safety %u", addr);
        return false;
    }

    uint8_t buf[4]{};
    memcpy(buf, tx, std::min<uint16_t>(4, tx_len));
    return _impl->nfca_write_page(addr, buf);
}

bool NFCLayerA::write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }

    uint8_t buf[16]{};
    memcpy(buf, tx, std::min<uint16_t>(16, tx_len));

    //
    if (_activePICC.supportsNFC()) {
        uint8_t epage = addr + 4 - 1;
        if (safety && (!is_user_block(_activePICC.type, addr) || !is_user_block(_activePICC.type, epage))) {
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
    if (safety && !is_user_block(_activePICC.type, addr)) {
        M5_LIB_LOGW("Write has been rejected due to safety %u", addr);
        return false;
    }
    return _impl->nfca_write_block(addr, buf);
}

bool NFCLayerA::write(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                      const m5::nfc::a::mifare::classic::Key& key)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.supportsNFC() ? write_using_write4(addr, tx, tx_len)
                                     : write_using_write16(addr, tx, tx_len, key);
}

bool NFCLayerA::write_using_write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len)
{
    const Type t        = _activePICC.type;
    const uint16_t last = get_last_user_block(t);
    uint16_t need_page  = ((tx_len + 3) >> 2);
    uint16_t from       = std::min<uint16_t>(_activePICC.blocks - 1, std::max<uint16_t>(addr, get_first_user_block(t)));
    uint16_t to         = std::min<uint16_t>(from + need_page - 1, last);
    uint16_t pages      = to - from + 1;
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
    const Type t    = _activePICC.type;
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

    uint16_t st_block{};
    while (written < tx_len) {
        uint8_t stb = get_sector_trailer_block(cur);
        if (stb != st_block) {
            st_block = stb;
            if (_activePICC.isMifareClassic()) {
                M5_LIB_LOGD("  AUTH:%u", st_block);
                if (!mifareClassicAuthenticateA(st_block, key)) {
                    M5_LIB_LOGE("Failed to AUTH %u", st_block);
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
    if (_activePICC.valid()) {
        if (_activePICC.isMifareClassic()) {
            return dump_sector_structure(_activePICC, mkey);
        } else if (_activePICC.supportsNFC()) {
            return dump_page_structure(_activePICC.blocks);
        }
        M5_LIB_LOGW("Not supported %s", _activePICC.typeAsString().c_str());
    }
    return false;
}

bool NFCLayerA::dump(const uint8_t block)
{
    if (_activePICC.valid()) {
        if (_activePICC.isMifareClassic()) {
            return dump_sector(get_sector(block));
        } else if (_activePICC.supportsNFC()) {
            return dump_page(block, _activePICC.blocks);
        }
        M5_LIB_LOGW("Not supported %s", _activePICC.typeAsString().c_str());
    }
    return false;
}

bool NFCLayerA::mifareClassicAuthenticateA(const uint8_t block, const m5::nfc::a::mifare::classic::Key& key)
{
    return _activePICC.valid() ? _impl->mifare_classic_authenticate(true, _activePICC, block, key) : false;
}

bool NFCLayerA::mifareClassicAuthenticateB(const uint8_t block, const m5::nfc::a::mifare::classic::Key& key)
{
    return _activePICC.valid() ? _impl->mifare_classic_authenticate(false, _activePICC, block, key) : false;
}

bool NFCLayerA::mifareClassicReadAccessCondition(uint8_t& c123, const uint8_t block)
{
    c123 = 0;

    uint8_t permissions[4]{};
    uint8_t st_block = get_sector_trailer_block(block);

    if (!_activePICC.isMifareClassic()) {
        return false;
    }

    uint8_t rbuf[16]{};
    if (!read16(rbuf, st_block)) {
        return false;
    }

    if (!decode_access_bits(permissions, rbuf + 6)) {
        M5_LIB_LOGE("Failed to decode access bits %u %02X:%02X:%02X:%02X",  //
                    st_block, rbuf[6], rbuf[7], rbuf[8], rbuf[9]);
        return false;
    }
    auto offset = get_permission_offset(block);
    c123        = permissions[offset];
    return true;
}

bool NFCLayerA::mifareClassicWriteAccessCondition(const uint8_t block, const uint8_t c123, const Key& akey,
                                                  const Key& bkey)
{
    uint8_t permissions[4]{};
    uint8_t st_block = get_sector_trailer_block(block);

    if (!_activePICC.isMifareClassic()) {
        return false;
    }

    uint8_t buf[16]{};
    if (!read16(buf, st_block)) {
        return false;
    }

    if (!decode_access_bits(permissions, buf + 6)) {
        M5_LIB_LOGE("Failed to decode access bits %u %02X:%02X:%02X:%02X",  //
                    st_block, buf[6], buf[7], buf[8], buf[9]);
        return false;
    }

    auto offset         = get_permission_offset(block);
    permissions[offset] = c123;

    if (!encode_access_bits(buf + 6, permissions)) {
        M5_LIB_LOGE("Failed to encode access bits %02X:%02X:%02X:%02X",  //
                    permissions[0], permissions[1], permissions[2], permissions[3]);
        return false;
    }
    // Since writes are performed in 16-byte units, key information must also be entered correctly
    memcpy(buf, akey.data(), 6);
    memcpy(buf + 10, bkey.data(), 6);

    return write16(st_block, buf, sizeof(buf), false /* Disable safety */);
}

bool NFCLayerA::mifareClassicIsValueBlock(bool& is_value_block, const uint8_t block)
{
    is_value_block = false;
    if (!_activePICC.isMifareClassic()) {
        return false;
    }
    if (!is_user_block(_activePICC.type, block)) {
        return true;
    }

    uint8_t st_block = get_sector_trailer_block(block);
    uint8_t buf[16]{}, stbuf[16]{};

    if (!read16(buf, block)) {
        M5_LIB_LOGE("Failed to read %u", block);
        return false;
    }
    if (!read16(stbuf, st_block)) {
        M5_LIB_LOGE("Failed to read %u", st_block);
        return false;
    }

    uint8_t permissions[4]{};
    auto offset = get_permission_offset(block);
    if (!decode_access_bits(permissions, stbuf + 6)) {
        M5_LIB_LOGE("Failed to decode access bits %u/%u %02X:%02X:%02X:%02X",  //
                    block, st_block, stbuf[6], stbuf[7], stbuf[8], stbuf[9]);
        return false;
    }
    int32_t value{};
    uint8_t addr{};
    is_value_block = can_value_block_permission(permissions[offset]) && decode_value_block(value, addr, buf);
    return true;
}

bool NFCLayerA::mifareClassicReadValueBlock(int32_t& value, const uint8_t block)
{
    value = 0;
    if (!_activePICC.isMifareClassic() || !is_user_block(_activePICC.type, block)) {
        return false;
    }

    uint8_t buf[16]{};
    if (!read16(buf, block)) {
        return false;
    }

    uint8_t addr{};
    int32_t v{};
    if (!decode_value_block(v, addr, buf)) {
        M5_LIB_LOGE("Failed to value block %u", block);
        M5_DUMPE(buf, sizeof(buf));
        return false;
    }

    if (addr == block) {
        value = v;
        return true;
    }
    return false;
}

bool NFCLayerA::mifareClassicWriteValueBlock(const uint8_t block, const int32_t value)
{
    if (!_activePICC.isMifareClassic() || !is_user_block(_activePICC.type, block)) {
        return false;
    }

    uint8_t buf[16]{};
    encode_value_block(buf, value, block);
    return write16(block, buf, sizeof(buf));
}

bool NFCLayerA::mifareClassicDecrementValueBlock(const uint8_t block, const uint32_t delta, const bool transfer)
{
    if (!_activePICC.isMifareClassic() || !mifare_classic_value_block(Command::DECREMENT, block, delta)) {
        return false;
    }
    return transfer ? mifareClassicTransferValueBlock(block) : true;
}

bool NFCLayerA::mifareClassicIncrementValueBlock(const uint8_t block, const uint32_t delta, const bool transfer)
{
    if (!_activePICC.isMifareClassic() || !mifare_classic_value_block(Command::INCREMENT, block, delta)) {
        return false;
    }
    return transfer ? mifareClassicTransferValueBlock(block) : true;
}

bool NFCLayerA::mifareClassicTransferValueBlock(const uint8_t block)
{
    return _activePICC.isMifareClassic() && mifare_classic_value_block(Command::TRANSFER, block);
}

bool NFCLayerA::mifareClassicRestoreValueBlock(const uint8_t block)
{
    return _activePICC.isMifareClassic() && mifare_classic_value_block(Command::RESTORE, block);
}

bool NFCLayerA::mifareUltralightChangeFormatToNTAG()
{
    if (!_activePICC.supportsNFC()) {
        return false;
    }

    if (_activePICC.type == Type::MIFARE_Ultralight || _activePICC.type == Type::MIFARE_UltralightC) {
        if (!ntag_check_format()) {
            uint8_t buf[4] = {MAGIC_NO, 0x10 /* version 1.0 */, (uint8_t)(_activePICC.userAreaSize() / 8), 0x00};
            if (!write4(3 /* CC */, buf, sizeof(buf))) {
                M5_LIB_LOGE("Failed to write4");
                return false;
            }
            // Verify
            return ntag_check_format();
        }
    }
    return true;
}

bool NFCLayerA::ndefIsValidFormat(bool& valid)
{
    valid = false;
    return ntag_check_cc_valid() && _ndef.isValidFormat(_activePICC.nfcForumTagType(), valid);
}

bool NFCLayerA::ndefRead(m5::nfc::ndef::TLV& msg)
{
    msg = TLV{};

    std::vector<TLV> tlvs{};
    if (ndefRead(tlvs, tagBitsMessage)) {
        msg = !tlvs.empty() ? tlvs.front() : TLV{};
        return true;
    }
    return false;
}

bool NFCLayerA::ndefRead(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    return _activePICC.supportsNFC() && _ndef.read(_activePICC.nfcForumTagType(), tlvs, tagBits);
}

bool NFCLayerA::ndefWrite(const m5::nfc::ndef::TLV& msg)
{
    std::vector<TLV> tlvs = {msg};
    return msg.isMessageTLV() && _activePICC.supportsNFC() && _ndef.write(_activePICC.nfcForumTagType(), tlvs);
}

bool NFCLayerA::ndefWrite(const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    return _activePICC.supportsNFC() && _ndef.write(_activePICC.nfcForumTagType(), tlvs, false);
}

//
bool NFCLayerA::dump_sector_structure(const PICC& picc, const Key& key)
{
    uint8_t sectors = get_number_of_sectors(picc.type);
    if (!sectors) {
        return false;
    }

    puts(
        "Sec[Blk]:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F [Access]\n"
        "-----------------------------------------------------------------");

    for (int_fast8_t sector = 0; sector < sectors; ++sector) {
        auto sblock = get_sector_trailer_block_from_sector(sector);
        if (mifareClassicAuthenticateA(sblock, key)) {
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
                   can_value_block_permission(permission));
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

bool NFCLayerA::push_back_picc(std::vector<m5::nfc::a::PICC>& v, const m5::nfc::a::PICC& picc)
{
    // Keep unique valid PICC
    // std::set cannot use for it, Cannot PICC < PICC
    auto it = std::find_if(v.begin(), v.end(),
                           [&picc](const PICC& u) { return std::memcmp(u.uid, picc.uid, picc.size) == 0; });
    // New uid
    if (it == v.end()) {
        v.push_back(picc);
        return true;
    }
    // Overwrite?
    if (!it->valid() && picc.valid()) {
        *it = picc;
        return true;
    }
    return false;
}

bool NFCLayerA::mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block, const uint32_t arg)
{
    return _impl->mifare_classic_value_block(cmd, block, arg);
}

bool NFCLayerA::ntag_check_cc_valid()
{
    if (_activePICC.type == Type::MIFARE_Ultralight || _activePICC.type == Type::MIFARE_UltralightC) {
        if (!ntag_check_format()) {
            M5_LIB_LOGW("NOT NTAG CC %s", _activePICC.typeAsString().c_str());
            return false;
        }
    }
    return _activePICC.supportsNFC();
}

bool NFCLayerA::ntag_check_format()
{
    if (_activePICC.supportsNFC()) {
        // Need check CC(Capability Container)
        if (_activePICC.type == Type::MIFARE_Ultralight || _activePICC.type == Type::MIFARE_UltralightC) {
            uint8_t rbuf[16]{};
            if (!read16(rbuf, 0 /* page 0-3 */)) {
                M5_LIB_LOGE("Failed to read 0-3");
                return false;
            }
            if (rbuf[12] != MAGIC_NO || rbuf[13] < 0x10 /* version */) {
                M5_LIB_LOGE("Illegal CC %02X:%02X:%02X:%02X", rbuf[12], rbuf[13], rbuf[14], rbuf[15]);
                return false;
            }
        }
        return true;
    }
    return false;
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr)
{
    if (!rx || !rx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.canFastRead() ? read_using_fast(rx, rx_len, saddr)
                                     : read_using_read16(rx, rx_len, saddr, DEFAULT_KEY);
}

bool NFCLayerA::write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.supportsNFC() ? write_using_write4(saddr, tx, tx_len)
                                     : write_using_write16(saddr, tx, tx_len, DEFAULT_KEY);
}

uint16_t NFCLayerA::firstUserBlock() const
{
    return _activePICC.firstUserBlock();
}

uint16_t NFCLayerA::lastUserBlock() const
{
    return _activePICC.lastUserBlock();
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
