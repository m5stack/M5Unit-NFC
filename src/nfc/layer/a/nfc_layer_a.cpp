/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.cpp
  @brief Common layer for NFC-A
*/
#include "nfc_layer_a.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include "nfc/isoDEP/file_system.hpp"
#include "nfc/isoDEP/desfire_file_system.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>
#include <mbedtls/aes.h>
#include <esp_random.h>

using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;
using namespace m5::nfc::a::mifare::desfire;
using namespace m5::nfc::ndef;

namespace {

constexpr char dump_sector_header[] =
    "Sec[Blk]:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F [Access]\n"
    "-----------------------------------------------------------------";

bool is_not_user_block(const uint8_t block)
{
    return block == 0 || is_sector_trailer_block(block);
}

void print_block(const uint8_t buf[16], const int16_t block = -1, const int16_t sector = -1, const uint8_t ab = 0xFF,
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

void rotate_byte_left(uint8_t out[8], const uint8_t in[8])
{
    for (int i = 0; i < 7; ++i) {
        out[i] = in[i + 1];
    }
    out[7] = in[0];
}

uint16_t mifare_plus_key_no(const uint8_t sector, const bool key_b)
{
    return static_cast<uint16_t>(0x4000 + sector * 2 + (key_b ? 1 : 0));
}

void cmac_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    uint8_t l[16]{};
    uint8_t zero[16]{};
    mbedtls_aes_context aes{};
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, zero, l);
    mbedtls_aes_free(&aes);

    uint8_t msb = l[0] & 0x80;
    for (int i = 0; i < 15; ++i) {
        k1[i] = (uint8_t)((l[i] << 1) | (l[i + 1] >> 7));
    }
    k1[15] = (uint8_t)(l[15] << 1);
    if (msb) {
        k1[15] ^= 0x87;
    }

    msb = k1[0] & 0x80;
    for (int i = 0; i < 15; ++i) {
        k2[i] = (uint8_t)((k1[i] << 1) | (k1[i + 1] >> 7));
    }
    k2[15] = (uint8_t)(k1[15] << 1);
    if (msb) {
        k2[15] ^= 0x87;
    }
}

void mifare_plus_data_crypt_block(const uint8_t key[16], const uint8_t iv_in[16], const uint8_t in[16], uint8_t out[16],
                                  const bool decrypt)
{
    uint8_t iv[16]{};
    memcpy(iv, iv_in, sizeof(iv));
    mbedtls_aes_context aes{};
    mbedtls_aes_init(&aes);
    if (decrypt) {
        mbedtls_aes_setkey_dec(&aes, key, 128);
    } else {
        mbedtls_aes_setkey_enc(&aes, key, 128);
    }
    mbedtls_aes_crypt_cbc(&aes, decrypt ? MBEDTLS_AES_DECRYPT : MBEDTLS_AES_ENCRYPT, 16, iv, in, out);
    mbedtls_aes_free(&aes);
}

void cmac_aes_128_8(const uint8_t* key, const uint8_t* msg, size_t msg_len, uint8_t out[8])
{
    uint8_t k1[16]{};
    uint8_t k2[16]{};
    cmac_subkeys(key, k1, k2);

    const bool complete = (msg_len > 0 && (msg_len % 16 == 0));
    const size_t blocks = (msg_len + 15) / 16;
    uint8_t last[16]{};
    if (blocks == 0) {
        last[0] = 0x80;
        for (int i = 0; i < 16; ++i) {
            last[i] ^= k2[i];
        }
    } else {
        const uint8_t* tail = msg + 16 * (blocks - 1);
        if (complete) {
            memcpy(last, tail, 16);
            for (int i = 0; i < 16; ++i) {
                last[i] ^= k1[i];
            }
        } else {
            const size_t rem = msg_len % 16;
            memcpy(last, tail, rem);
            last[rem] = 0x80;
            for (int i = 0; i < 16; ++i) {
                last[i] ^= k2[i];
            }
        }
    }

    uint8_t x[16]{};
    uint8_t y[16]{};
    mbedtls_aes_context aes{};
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    for (size_t i = 0; i + 1 < blocks; ++i) {
        const uint8_t* blk = msg + 16 * i;
        for (int j = 0; j < 16; ++j) {
            y[j] = x[j] ^ blk[j];
        }
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, y, x);
    }
    for (int j = 0; j < 16; ++j) {
        y[j] = x[j] ^ last[j];
    }
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, y, x);
    mbedtls_aes_free(&aes);

    for (int i = 0; i < 8; ++i) {
        out[i] = x[i * 2 + 1];
    }
}

enum class MfpMacType {
    ReadCmd,
    ReadResp,
    WriteCmd,
    WriteResp,
};

bool mifare_plus_calculate_mac(const uint8_t kmac[16], const uint8_t ti[4], const uint16_t r_ctr, const uint16_t w_ctr,
                               const MfpMacType type, const uint8_t block, const uint8_t count, const uint8_t* data,
                               const size_t data_len, uint8_t out[8])
{
    if (!kmac || !ti || !data || data_len == 0 || !out) {
        return false;
    }

    uint16_t ctr = r_ctr;
    if (type == MfpMacType::WriteCmd || type == MfpMacType::WriteResp) {
        ctr = w_ctr;
    }

    uint8_t macdata[2049]{};
    macdata[0] = data[0];
    macdata[1] = (uint8_t)(ctr & 0xFF);
    macdata[2] = (uint8_t)(ctr >> 8);
    macdata[3] = 0x00;
    memcpy(&macdata[3], ti, 4);

    size_t mac_len = data_len + 6;
    switch (type) {
        case MfpMacType::ReadCmd:
            memcpy(&macdata[7], &data[1], data_len - 1);
            break;
        case MfpMacType::ReadResp:
            macdata[7] = block;
            macdata[8] = 0x00;
            macdata[9] = count;
            memcpy(&macdata[10], &data[1], data_len - 1);
            mac_len = data_len + 9;
            break;
        case MfpMacType::WriteCmd:
            memcpy(&macdata[7], &data[1], data_len - 1);
            break;
        case MfpMacType::WriteResp:
            mac_len = 1 + 6;
            break;
    }

    cmac_aes_128_8(kmac, macdata, mac_len, out);
    return true;
}

constexpr int8_t kAccessDenied{-1};
constexpr int8_t kAccessFree{-2};
int8_t required_read_key_no_from_access_rights(const uint16_t access_rights)
{
    const uint8_t read_key = (access_rights >> 12) & 0x0F;
    const uint8_t rw_key   = (access_rights >> 4) & 0x0F;
    if (read_key == 0x0E) {
        return kAccessFree;
    }
    if (read_key != 0x0F) {
        return read_key;
    }
    if (rw_key == 0x0E) {
        return kAccessFree;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return kAccessDenied;
}

}  // namespace

namespace m5 {
namespace nfc {

bool NFCLayerA::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                           const uint32_t timeout_ms)
{
    return _impl->transceive(rx, rx_len, tx, tx_len, timeout_ms);
}

#if 0
bool NFCLayerA::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return false;
}

bool NFCLayerA::receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    return false;
}
#endif

m5::nfc::NFCForumTag NFCLayerA::supportsNFCTag() const
{
    return _activePICC.nfcForumTagType();
}

file_system_feature_t NFCLayerA::supportsFilesystem() const
{
    return _activePICC.fileSystemFeature();
}

bool NFCLayerA::request(uint16_t& atqa)
{
    return _impl->request(atqa);
}

bool NFCLayerA::wakeup(uint16_t& atqa)
{
    auto ret = _impl->wakeup(atqa);
    m5::utility::delay(2);
    return ret;
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

    do {
        PICC picc{};

        // Exists PICC?
        if (!request(picc.atqa)) {
            m5::utility::delay(1);
            continue;
        }
        M5_LIB_LOGE("ATQA:%04X", picc.atqa);

        // Select
        if (!select(picc)) {
            return false;
        }

        M5_LIB_LOGE("Detect:ATQA:%04X SAK:%02X %s (%s)", picc.atqa, picc.sak, picc.uidAsString().c_str(),
                    picc.typeAsString().c_str());

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
    _activePICC = PICC{};
    if (_impl->select(picc)) {
        if (picc.isISO14443_4() && !picc.isMifareClassicCompatible()) {
            if (!nfca_request_ats(picc.ats)) {
                return false;
            }
        }
        _activePICC = picc;
        return true;
    }
    return false;
}

bool NFCLayerA::activate(const PICC& picc, const bool force_rats)
{
    _activePICC = PICC{};
    if (_impl->activate(picc)) {
        // M5_LIB_LOGE(" >>>> SEL");
        if (force_rats || (picc.isISO14443_4() && !picc.isMifareClassicCompatible())) {
            // M5_LIB_LOGE("   >>>> RATS");
            ATS discard{};
            if (!nfca_request_ats(discard)) {
                M5_LIB_LOGE("Failed to RATS");
                return false;
            }
        }
        _activePICC = picc;
        M5_LIB_LOGV("ACTIVATED %s %u", _activePICC.uidAsString().c_str(), _activePICC.isISO14443_4());
        return true;
    }
    M5_LIB_LOGE("Failed to activate");
    return false;
}

bool NFCLayerA::reactivate(const PICC& picc, const bool force_rats)
{
    PICC tmp = picc;
    if (_activePICC.valid()) {
        if (!deactivate()) {
            M5_LIB_LOGE("Failed to deactivate");
            return false;
        }
    }
    uint16_t discard{};
    if (!wakeup(discard)) {
        M5_LIB_LOGE("Failed to wakeup");
        return false;
    }
    if (!activate(tmp, force_rats)) {
        M5_LIB_LOGE("Failed to activate");
        return false;
    }
    return true;
}

bool NFCLayerA::deactivate()
{
    auto tmp    = _activePICC;
    _activePICC = PICC{};

    auto ret = false;
    if (tmp.isMifareClassicCompatible()) {
        ret = _impl->hlt();
    } else {
        ret = tmp.isISO14443_4() ? nfca_deselect() : _impl->hlt();
    }
    m5::utility::delay(2);
    return ret;
}

bool NFCLayerA::identify(m5::nfc::a::PICC& picc)
{
    bool ret = identify_picc(picc);
    deactivate();
    return ret;
}

bool NFCLayerA::identify_picc(m5::nfc::a::PICC& picc)
{
    Type type{};

    if (!reactivate(picc)) {
        return false;
    }

    // ISO_14443_4 ->
    if (picc.type == Type::ISO_14443_4) {
        // GetVersion(L4)
        uint8_t ver4[64]{};
        uint16_t ver_len = sizeof(ver4);
        if (mifare_get_version_L4_wrapped(ver4, ver_len)) {
            // Plus EV(SL3),DESFire,NTAG4xx
            // M5_LIB_LOGE(">>>> GetVerionL4 OK %02X/%04X", picc.sak, picc.atqa);
            // m5::utility::log::dump(ver4, ver_len, false);
            type = version4_to_type(picc.sub_type, ver4);
        } else {
            // Plus S/X (SL0/3),EV1/2 (SL0) ST25TA
            //  Check historical bytes
            // M5_LIB_LOGE(">>>> Check historical bytes %02X/%04X", picc.sak, picc.atqa);
            // m5::utility::log::dump(picc.ats.historical.data(), picc.ats.historical_len, false);
            type = historical_bytes_to_type(picc.sub_type, picc.atqa, picc.sak, picc.ats.historical.data(),
                                            picc.ats.historical_len);
            if (picc.sak == 0x20 && is_mifare_plus(type)) {
                uint16_t discard{};
                if (nfca_deselect() && wakeup(discard) && _impl->activate(picc)) {
                    // Plus SL0/3
                    picc.security_level = identify_plus_sl03();
                    _impl->hlt();
                    _activePICC = {};
                }
            }
        }
        if (type != Type::Unknown) {
            picc.type   = type;
            picc.blocks = get_number_of_blocks(picc.type);
            return true;
        }

        // ST25TA series?
        if (picc.uid[0] == m5::stl::to_underlying(ManufacturerId::STMicroelectronics)) {
            type = identify_picc_st25ta();
            if (type != Type::Unknown) {
                picc.type   = type;
                picc.blocks = get_number_of_blocks(picc.type);
                return true;
            }
        }

        // Not changed
        return reactivate(picc);
    }

    // Ultralight ->
    if (picc.type == Type::MIFARE_Ultralight) {
        uint8_t ver[8]{};
        // GetVersion(L3)
        if (mifare_get_version_L3(ver)) {
            // M5_LIB_LOGE("L3 OK");
            // m5::utility::log::dump(ver, 8, false);
            //  ULEV, UL Nano, NTAG2xx
            picc.type   = version3_to_type(ver);
            picc.blocks = get_number_of_blocks(picc.type);
            return true;
        }
        //  The PICC goes idle when sending an external command, so select again
        if (!reactivate(picc)) {
            return false;
        }
        // Try ULC Auth
        uint8_t discard_ek[8]{};
        picc.type   = mifare_ultralightC_authenticate1(discard_ek) ? Type::MIFARE_UltralightC : Type::MIFARE_Ultralight;
        picc.blocks = get_number_of_blocks(picc.type);
        return true;
    }

    // Classic ->
    if (picc.isMifareClassic() && !picc.isMifarePlus()) {
        ATS ats{};
        if (nfca_request_ats(ats)) {
            picc.ats = ats;

            uint8_t ver4[64]{};
            uint16_t ver_len = sizeof(ver4);
            if (mifare_get_version_L4_raw(ver4, ver_len)) {
                // Plus EV1 SL1
                type = version4_to_type(picc.sub_type, ver4);
            } else {
                // Plus S/X/SE SL1
                type = historical_bytes_to_type(picc.sub_type, picc.atqa, picc.sak, ats.historical.data(),
                                                ats.historical_len);
            }
            if (!nfca_deselect()) {
                M5_LIB_LOGD("Failed to deselect after RATS for Plus SL1");
            }
            if (is_mifare_plus(type)) {
                picc.type           = type;
                picc.blocks         = get_number_of_blocks(picc.type);
                picc.security_level = 1;
                return true;
            }
        }
    }

    // M5_LIB_LOGE(" Not changed");
    //  Not changed
    return true;
}

m5::nfc::a::Type NFCLayerA::identify_picc_st25ta()
{
    st25ta::SystemFile sf{};

    // Read ST25TA system file
    FileSystem fs(_isoDEP);
    const bool selected_df = fs.selectDfNameAuto(type4::NDEF_AID, sizeof(type4::NDEF_AID));
    if (!selected_df) {
        return Type::Unknown;
    }
    const bool selected_cc = fs.selectFileIdAuto(st25ta::SYSTEM_FILE_ID);
    if (!selected_cc) {
        return Type::Unknown;
    }

    // Check length
    std::vector<uint8_t> head;
    if (!fs.readBinary(head, 0, 2) || head.size() < 2) {
        return Type::Unknown;
    }
    const uint16_t cc_len = (static_cast<uint16_t>(head[0]) << 8) | head[1];
    if (cc_len != sizeof(sf)) {
        return Type::Unknown;
    }

    // Read
    std::vector<uint8_t> raw;
    raw.reserve(cc_len);
    uint16_t offset = 0;
    while (offset < cc_len) {
        const uint16_t chunk = std::min<uint16_t>(static_cast<uint16_t>(cc_len - offset), 0xFF);
        std::vector<uint8_t> part;
        if (!fs.readBinary(part, offset, chunk) || part.size() < chunk) {
            return Type::Unknown;
        }
        raw.insert(raw.end(), part.begin(), part.end());
        offset = static_cast<uint16_t>(offset + chunk);
    }
    if (raw.size() < cc_len) {
        return Type::Unknown;
    }
    return st25ta::get_type(raw[17]);
}

uint8_t NFCLayerA::identify_plus_sl03()
{
    // Heuristic SL0 check: try WritePerso-like command
    uint8_t sl0_probe[] = {0xA8, 0x90, 0x90, 0x00};
    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    //    if (_isoDEP.transceiveINF(rx, rx_len, sl0_probe, sizeof(sl0_probe)) && rx_len >= 1) {
    _impl->transceive(rx, rx_len, sl0_probe, sizeof(sl0_probe), 10);
    return rx_len ? 0 : 3;  // SL0 if there is a response
}

bool NFCLayerA::read4(uint8_t rx[4], const uint8_t addr)
{
    if (!rx || !_activePICC.valid()) {
        return false;
    }

    uint16_t rx_len{4};
    if (_activePICC.canFastRead()) {
        return ntag_read_page(rx, rx_len, addr, addr);
    }
    uint8_t tmp[16]{};
    if (_impl->nfca_read_block(tmp, addr & ~0x03)) {
        memcpy(rx, tmp + 4 * (addr & 0x03), 4);
        return true;
    }
    return false;
}

bool NFCLayerA::read16(uint8_t rx[16], const uint8_t addr)
{
    uint16_t rx_len{16};
    return rx && _activePICC.valid() &&
           (_activePICC.canFastRead() ? (ntag_read_page(rx, rx_len, addr, addr + 3) && rx_len == 16)
                                      : _impl->nfca_read_block(rx, addr));
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t addr, const m5::nfc::a::mifare::classic::Key& key)
{
    if (!rx || !rx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.canFastRead() ? read_using_fast(rx, rx_len, addr) : read_using_read16(rx, rx_len, addr, key);
}

bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t addr, const m5::nfc::a::mifare::plus::AESKey& key)
{
    if (!rx || !rx_len || !_activePICC.valid()) {
        return false;
    }
    if (!_activePICC.isMifarePlus() || _activePICC.security_level != 3) {
        return false;
    }

    uint16_t need_block = ((rx_len + 15) >> 4);
    uint16_t last       = get_last_user_block(_activePICC.type);
    uint16_t from       = addr;
    uint16_t to         = std::min<uint16_t>(from + need_block - 1, last);
    uint16_t blocks     = to - from + 1;

    uint16_t read_size = blocks << 4;  // 16 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGE("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
        rx_len = 0;
        return false;
    }

    rx_len = 0;
    uint8_t last_sec{0xFF};
    uint16_t actual{};
    uint16_t cur = from;

    M5_LIB_LOGV("READ:blocks:%u-%u %u %u", from, to, blocks, _activePICC.blocks);

    while (actual < blocks && cur <= last) {
        m5::utility::delay(1);
        const uint8_t sec = get_sector(cur);
        if (sec != last_sec) {
            last_sec        = sec;
            uint16_t key_no = mifare_plus_key_no(sec, false);
            M5_LIB_LOGV("   AUTH:%u/%u", cur, sec);
            if (!mifare_plus_authenticateAES(key_no, key)) {
                M5_LIB_LOGE("Failed to AUTH %u", sec);
                return false;
            }
        }
        // Skip sector trailer and  block 0
        if (is_not_user_block(cur)) {
            ++cur;
            continue;
        }
        M5_LIB_LOGV("   READ:%u %u/%u", cur, actual, blocks);
        std::vector<uint8_t> data{};
        if (!mifare_plus_read_mac_l4(cur, 1, data, false) || data.size() < 16) {
            M5_LIB_LOGE("Failed to read block:%u", cur);
            return false;
        }
        memcpy(rx + 16 * actual, data.data(), 16);
        rx_len += 16;
        ++cur;
        ++actual;
    }
    return true;
}

bool NFCLayerA::read_using_read16(uint8_t* rx, uint16_t& rx_len, const uint8_t addr,
                                  const m5::nfc::a::mifare::classic::Key& key)
{
    uint16_t need_block = ((rx_len + 15) >> 4);
    uint16_t last       = get_last_user_block(_activePICC.type);
    uint16_t from       = addr;
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

    M5_LIB_LOGE("READ:blocks:%u-%u %u %u (%u)", from, to, blocks, _activePICC.blocks, add);

    while (actual < blocks && cur <= last) {
        uint16_t stb = get_sector_trailer_block(cur);
        if (stb != st_block) {
            st_block = stb;
            if (_activePICC.isMifareClassic()) {
                M5_LIB_LOGV("   AUTH:%u/%u", cur, st_block);
                if (!mifareClassicAuthenticateA(st_block, key)) {
                    M5_LIB_LOGE("Failed to AUTH %u", st_block);
                    return false;
                }
            }
        }
        // Skip sector trailer and  block 0
        if (_activePICC.isMifareClassic() && is_not_user_block(cur)) {
            ++cur;
            continue;
        }
        M5_LIB_LOGV("   READ:%u %u/%u", cur, actual, blocks);
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

bool NFCLayerA::read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    const Type t = _activePICC.type;
    //  ST25R3916 512 but cannot use long length...why?
    uint16_t fifo_depth = std::min<uint16_t>(_impl->max_fifo_depth(), 64);

    const uint16_t last = get_last_user_block(t);
    uint16_t need_page  = ((rx_len + 3) >> 2);
    uint16_t from       = addr;
    uint16_t to         = std::min<uint16_t>(from + need_page - 1, last);
    uint16_t pages      = to - from + 1;

    uint16_t read_size = pages << 2;  // 4 byte unit
    if (read_size > rx_len) {
        M5_LIB_LOGD("Not enough rx size %u-%u %u/%u", from, to, rx_len, read_size);
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

        if (!ntag_read_page(rx + rx_len, len, spage, epage) || len != (ps << 2)) {
            M5_LIB_LOGD("Failed to read %u-%u", spage, epage);
            return false;
        }
        rx_len += len;
        actual += ps;
        spage += ps;
        epage += ps;
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
    return ntag_write_page(addr, buf);
}

bool NFCLayerA::write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }

    uint8_t buf[16]{};
    memcpy(buf, tx, std::min<uint16_t>(16, tx_len));

    // page base
    if (_activePICC.supportsNFC()) {
        uint8_t epage = addr + 4 - 1;
        if (safety && (!is_user_block(_activePICC.type, addr) || !is_user_block(_activePICC.type, epage))) {
            M5_LIB_LOGW("Write has been rejected due to safety %u-%u", addr, epage);
            return false;
        }
        for (uint_fast8_t i = 0; i < 4; ++i) {
            if (!ntag_write_page(addr + i, buf + i * 4)) {
                return false;
            }
        }
        return true;
    }

    // sector base
    if (safety && is_not_user_block(addr)) {
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

bool NFCLayerA::write(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                      const m5::nfc::a::mifare::plus::AESKey& key)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }
    if (!_activePICC.isMifarePlus() || _activePICC.security_level != 3) {
        return false;
    }

    const Type t    = _activePICC.type;
    uint16_t last   = get_last_user_block(t);
    uint16_t blocks = (tx_len + 15) >> 4;
    uint16_t b{};
    while (b < blocks) {
        if (addr + b > last) {
            M5_LIB_LOGW("Write has been rejected out of user block range %u-%u", addr, addr + blocks - 1);
            return false;
        }
        b += (1 + is_not_user_block(addr + b));
    }

    uint8_t cur = addr;
    uint16_t written{};
    const uint8_t* data = tx;
    uint8_t last_sec{0xFF};

    M5_LIB_LOGV("WRITE:%u,%u %u- %u", addr, tx_len, cur, blocks);

    while (written < tx_len) {
        uint16_t sector = get_sector(cur);
        if (sector != last_sec) {
            last_sec        = sector;
            uint16_t key_no = mifare_plus_key_no((uint8_t)sector, false);
            M5_LIB_LOGV("  AUTH:%u", last_sec);
            if (!mifare_plus_authenticateAES(key_no, key)) {
                M5_LIB_LOGE("Failed to AUTH %u", last_sec);
                break;
            }
        }
        if (is_not_user_block(cur)) {
            ++cur;
            continue;
        }
        uint16_t sz = std::min<uint16_t>(16, tx_len - written);
        M5_LIB_LOGV("  WRITE:%u %u %u/%u", cur, sz, written, tx_len);
        if (!mifare_plus_write_mac_l4(cur, data, sz, false)) {
            break;
        }
        written += sz;
        data += sz;
        ++cur;
    }

    return written == tx_len;
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
        M5_LIB_LOGD("The write start position is not in the user area %u/%u", addr, from);
        return false;
    }

    if (tx_len > total) {
        M5_LIB_LOGD("Not enough user area from %u-%u %u/%u", from, to, tx_len, total);
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
                                                 //        b += (1 + is_not_user_block(addr + b));
    }

    uint8_t cur = addr;
    uint16_t written{0};
    const uint8_t* data = tx;

    M5_LIB_LOGV("WRITE:%u,%u %u- %u", addr, tx_len, cur, blocks);

    uint16_t st_block{};
    while (written < tx_len) {
        uint8_t stb = get_sector_trailer_block(cur);
        if (stb != st_block) {
            st_block = stb;
            if (_activePICC.isMifareClassic()) {
                M5_LIB_LOGV("  AUTH:%u", st_block);
                if (!mifareClassicAuthenticateA(st_block, key)) {
                    M5_LIB_LOGD("Failed to AUTH %u", st_block);
                    break;
                }
            }
        }
        if (_activePICC.isMifareClassic() && is_not_user_block(cur)) {
            ++cur;
            continue;
        }

        uint16_t sz = std::min<uint16_t>(16, tx_len - written);
        M5_LIB_LOGV("  WRITE:%u %u %u/%u", cur, sz, written, tx_len);
        if (!write16(cur, data, sz)) {
            M5_LIB_LOGE("write failed %u", cur);
            break;
        }
        written += sz;
        data += sz;
        ++cur;
    }
    M5_LIB_LOGE(">>>>%u %u", written, tx_len);

    return written == tx_len;
}

bool NFCLayerA::dump(const Key& mkey)
{
    if (_activePICC.valid()) {
        if (_activePICC.isMifareClassic()) {
            return dump_sector_structure(_activePICC, mkey);
        } else if (_activePICC.isMifarePlus() && _activePICC.security_level == 3) {
            return dump_mifare_plus_sl3(plus::DEFAULT_FF_KEY);
        } else if (_activePICC.supportsNFC()) {
            return dump_page_structure(_activePICC.blocks);
        } else if (_activePICC.isMifareDESFire()) {
            return _activePICC.type == Type::MIFARE_DESFire_Light ? dump_desfire_light() : dump_desfire();
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
        } else if (_activePICC.isMifarePlus() && _activePICC.security_level == 3) {
            const uint8_t sector  = get_sector(block);
            const uint16_t key_no = mifare_plus_key_no(sector, false);
            if (!mifare_plus_authenticateAES(key_no, plus::DEFAULT_FF_KEY)) {
                M5_LIB_LOGE("SL3 auth failed for dump sector %u", sector);
                return false;
            }
            return dump_sector_mifare_plus_sl3(sector);
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
        M5_LIB_LOGD("Failed to decode access bits %u %02X:%02X:%02X:%02X",  //
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
        M5_LIB_LOGD("Failed to decode access bits %u %02X:%02X:%02X:%02X",  //
                    st_block, buf[6], buf[7], buf[8], buf[9]);
        return false;
    }

    auto offset         = get_permission_offset(block);
    permissions[offset] = c123;

    if (!encode_access_bits(buf + 6, permissions)) {
        M5_LIB_LOGD("Failed to encode access bits %02X:%02X:%02X:%02X",  //
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
    if (!_activePICC.isMifareClassic() || is_not_user_block(block)) {
        return true;
    }

    uint8_t st_block = get_sector_trailer_block(block);
    uint8_t buf[16]{}, stbuf[16]{};

    if (!read16(buf, block)) {
        M5_LIB_LOGD("Failed to read %u", block);
        return false;
    }
    if (!read16(stbuf, st_block)) {
        M5_LIB_LOGD("Failed to read %u", st_block);
        return false;
    }

    uint8_t permissions[4]{};
    auto offset = get_permission_offset(block);
    if (!decode_access_bits(permissions, stbuf + 6)) {
        M5_LIB_LOGD("Failed to decode access bits %u/%u %02X:%02X:%02X:%02X",  //
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
    if (!_activePICC.isMifareClassic() || is_not_user_block(block)) {
        return true;
    }

    uint8_t buf[16]{};
    if (!read16(buf, block)) {
        return false;
    }

    uint8_t addr{};
    int32_t v{};
    if (!decode_value_block(v, addr, buf)) {
        M5_LIB_LOGD("Failed to value block %u", block);
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
    if (!_activePICC.isMifareClassic() || is_not_user_block(block)) {
        return true;
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

bool NFCLayerA::mifareUltralightChangeFormatToNDEF()
{
    if (!_activePICC.supportsNFC() || !_activePICC.isMifareUltralight()) {
        return false;
    }

    type2::CapabilityContainer cc{};
    if (!_ndef.readCapabilityContainer(cc)) {
        return false;
    }

    if (cc.valid()) {  // Already NDEF format?
        return true;
    }

    cc.block[0] = MAGIC_NO_CC4;
    cc.major_version(NDEF_MAJOR_VERSION);
    cc.minor_version(NDEF_MINOR_VERSION);
    cc.ndef_size(_activePICC.userAreaSize());
    cc.read_access(ACCESS_FREE);
    cc.write_access(ACCESS_FREE);
    // m5::utility::log::dump(cc.block, 4, false);

    if (!write4(TYPE2_CC_BLOCK, cc.block, sizeof(cc.block), false)) {
        M5_LIB_LOGD("Failed to write");
        return false;
    }
    return true;
}

bool NFCLayerA::mifareUltralightCAuthenticate(const uint8_t key[16])
{
    using m5::utility::crypto::TripleDES;

    TripleDES::Key16 key16{};
    memcpy(key16.data(), key, 16);

    // Auth step 1. Receive ek(RndB)
    uint8_t ek_rndB[8]{};
    if (!mifare_ultralightC_authenticate1(ek_rndB)) {
        M5_LIB_LOGD("Failed to auth1");
        return false;
    }

    // Decrypt ek
    uint8_t iv[8]{};
    uint8_t rndB[8]{};
    {
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, iv};
        if (!des.decrypt(rndB, ek_rndB, sizeof(ek_rndB), key16)) {
            M5_LIB_LOGD("Failed to decrypt");
            return false;
        }
    }

    // Make rndA
    uint8_t rndA[8]{};
    for (auto& r : rndA) {
        r = esp_random();
    }

    // Make RndB',RandA'
    uint8_t rndB_rot[8]{};
    uint8_t rndA_rot[8]{};
    rotate_byte_left(rndB_rot, rndB);
    rotate_byte_left(rndA_rot, rndA);

    // Make plain
    uint8_t plain_AB[16]{};
    memcpy(plain_AB, rndA, 8);
    memcpy(plain_AB + 8, rndB_rot, 8);

    // Make ek(RndA || RndB')
    uint8_t ek_AB[16]{};
    {
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, ek_rndB};
        if (!des.encrypt(ek_AB, plain_AB, sizeof(plain_AB), key16)) {
            M5_LIB_LOGD("Failed to encrypt");
            return false;
        }
    }

    // Auth step 2. Send [AF || ek(RndA||RndB')], Receive [RndA']
    uint8_t ek_rndA_rot_from_card[8]{};
    if (!mifare_ultralightC_authenticate2(ek_rndA_rot_from_card, ek_AB)) {
        M5_LIB_LOGD("Failed to auth2");
        return false;
    }

    // Decrypt RndA'
    uint8_t rndA_rot_from_card[8]{};
    {
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, ek_AB + 8};
        if (!des.decrypt(rndA_rot_from_card, ek_rndA_rot_from_card, sizeof(ek_rndA_rot_from_card), key16)) {
            return false;
        }
    }

    // Compare
    if (memcmp(rndA_rot, rndA_rot_from_card, 8) != 0) {
        M5_LIB_LOGD("Not match");
        m5::utility::log::dump(rndA_rot, 8, false);
        m5::utility::log::dump(rndA_rot_from_card, 8, false);
        return false;
    }
    return true;
}

bool NFCLayerA::mifarePlusUpgradeSecurityLevel1(const mifare::plus::AESKey& card_config_key,
                                                const mifare::plus::AESKey& card_master_key,
                                                const mifare::plus::AESKey& l2_switch_key,
                                                const mifare::plus::AESKey& l3_switch_key,
                                                const mifare::plus::AESKey& aes_sector_key,
                                                const mifare::classic::Key& key_a, const mifare::classic::Key& key_b)
{
    if (!_activePICC.valid() || !_activePICC.isMifarePlus() || _activePICC.security_level != 0) {
        return false;
    }

    const uint16_t sectors = get_number_of_sectors(_activePICC.type);
    if (!sectors) {
        return false;
    }

    constexpr uint8_t access_bits_default[3]{0xFF, 0x07, 0x80};
    constexpr uint8_t gpb_default{0x69};

    uint8_t block[16]{};  // sector trailer
    std::memcpy(block, key_a.data(), key_a.size());
    std::memcpy(block + 6, access_bits_default, sizeof(access_bits_default));
    block[9] = gpb_default;
    std::memcpy(block + 10, key_b.data(), key_b.size());

    auto write_perso_block = [&](const uint16_t block_no, const uint8_t* data) -> bool {
        if (!data) {
            return false;
        }
        uint8_t tx[19]{};
        tx[0] = m5::stl::to_underlying(Command::WRITE_PERSO);
        tx[1] = (uint8_t)(block_no & 0xFF);
        tx[2] = (uint8_t)(block_no >> 8);
        memcpy(tx + 3, data, 16);

        uint8_t rx[2]{};
        uint16_t rx_len{sizeof(rx)};
        if (!_isoDEP.transceiveINF(rx, rx_len, tx, sizeof(tx)) || !rx_len || rx[0] != 0x90 || rx[1] != 0x00) {
            M5_LIB_LOGE("write perso %04X failed %u %02X/%02X", block, rx_len, rx[0], rx[1]);
            return false;
        }
        return true;
    };

    if (!write_perso_block(0x9001, card_config_key.data())) {
        return false;
    }
    if (!write_perso_block(0x9000, card_master_key.data())) {
        return false;
    }
    if ((_activePICC.sub_type == m5::stl::to_underlying(SubTypePlus::EV2) ||
         _activePICC.sub_type == m5::stl::to_underlying(SubTypePlus::X)) &&
        !write_perso_block(0x9002, l2_switch_key.data())) {
        return false;
    }
    if (!write_perso_block(0x9003, l3_switch_key.data())) {
        return false;
    }

    for (uint16_t sector = 0; sector < sectors; ++sector) {
        const uint16_t key_a_no = mifare_plus_key_no((uint8_t)sector, false);
        const uint16_t key_b_no = mifare_plus_key_no((uint8_t)sector, true);
        if (!write_perso_block(key_a_no, aes_sector_key.data())) {
            return false;
        }
        if (!write_perso_block(key_b_no, aes_sector_key.data())) {
            return false;
        }
    }

    for (uint16_t sector = 0; sector < sectors; ++sector) {
        const uint16_t st_block = get_sector_trailer_block_from_sector(sector);
        if (!write_perso_block(st_block, block)) {
            return false;
        }
    }

    uint8_t commit_cmd[1]{m5::stl::to_underlying(Command::COMMIT_PERSO)};
    uint8_t rx[2]{};
    uint16_t rx_len{sizeof(rx)};
    if (!_isoDEP.transceiveINF(rx, rx_len, commit_cmd, sizeof(commit_cmd)) || !rx_len || rx[0] != 0x90 ||
        rx[1] != 0x00) {
        M5_LIB_LOGE("commit perso failed %u %02X/%02X", rx_len, rx[0], rx[1]);
        return false;
    }

    _activePICC.security_level = 1;
    return true;
}

bool NFCLayerA::mifarePlusUpgradeSecurityLevel2(const mifare::plus::AESKey& sl2_switch_key)
{
    if (!_activePICC.valid() || !_activePICC.isMifarePlus() || _activePICC.security_level != 1) {
        return false;
    }
    if (!(_activePICC.sub_type == m5::stl::to_underlying(SubTypePlus::EV2) ||
          _activePICC.sub_type == m5::stl::to_underlying(SubTypePlus::X))) {
        return false;
    }

    if (!mifare_plus_authenticateAES(0x9002, sl2_switch_key)) {
        M5_LIB_LOGE("SL2 auth failed");
        return false;
    }
    _activePICC.security_level = 2;
    return true;
}

bool NFCLayerA::mifarePlusUpgradeSecurityLevel3(const mifare::plus::AESKey& l3_switch_key)
{
    if (!_activePICC.valid() || !_activePICC.isMifarePlus()) {
        return false;
    }
    if (_activePICC.security_level != 1 && _activePICC.security_level != 2) {
        return false;
    }

    if (!mifare_plus_authenticateAES(0x9003, l3_switch_key)) {
        M5_LIB_LOGE("SL3 auth failed");
        return false;
    }

    _activePICC.security_level = 3;
    return true;
}

bool NFCLayerA::ndefIsValidFormat(bool& valid)
{
    valid = false;
    return _activePICC.supportsNDEF() ? _ndef.isValidFormat(valid, _activePICC.nfcForumTagType()) : false;
}

bool NFCLayerA::ndefPrepareDesfireLight()
{
    if (_activePICC.type != Type::MIFARE_DESFire_Light) {
        return false;
    }
    return _ndef.prepare_desfire_light();
}

bool NFCLayerA::ndefPrepareDesfire(const uint32_t max_ndef_size)
{
    if (!_activePICC.isMifareDESFire() || _activePICC.type == Type::MIFARE_DESFire_Light) {
        return false;
    }
    return _ndef.prepare_desfire(max_ndef_size);
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
    return _activePICC.supportsNDEF() && _ndef.read(_activePICC.nfcForumTagType(), tlvs, tagBits);
}

bool NFCLayerA::ndefWrite(const m5::nfc::ndef::TLV& msg)
{
    std::vector<TLV> tlvs = {msg};
    return msg.isMessageTLV() && _activePICC.supportsNDEF() && _ndef.write(_activePICC.nfcForumTagType(), tlvs);
}

bool NFCLayerA::ndefWrite(const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    return _activePICC.supportsNDEF() && _ndef.write(_activePICC.nfcForumTagType(), tlvs, false);
}

//
bool NFCLayerA::dump_sector_structure(const PICC& picc, const Key& key)
{
    uint8_t sectors = get_number_of_sectors(picc.type);
    if (!sectors) {
        return false;
    }

    puts(dump_sector_header);

    bool ret{true};
    for (int_fast8_t sector = 0; sector < sectors; ++sector) {
        auto sblock = get_sector_trailer_block_from_sector(sector);
        if (mifareClassicAuthenticateA(sblock, key)) {
            if (!dump_sector(sector)) {
                M5_LIB_LOGD("Failed to dump:%u", sector);
                return false;
            }
        } else {
            M5_LIB_LOGD("Failed to AUTH %u", sblock);
            return false;
        }
    }
    return ret;
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
        print_block(dbuf, base + i, (i == 0) ? sector : -1, show_permission ? permission : 0xFF, error,
                    can_value_block_permission(permission));
    }
    // Sector trailer
    print_block(sbuf, saddr, -1, permissions[3], error);

    return true;
}

bool NFCLayerA::dump_page_structure(const uint16_t maxPage)
{
    puts(
        "Page    :00 01 02 03\n"
        "--------------------");

    bool ret{true};
    for (uint_fast8_t page = 0; page < maxPage; page += 4) {
        ret &= dump_page(page, maxPage);
    }
    return ret;
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

bool NFCLayerA::dump_desfire()
{
    const auto cfg         = _isoDEP.config();
    uint16_t max_chunk_len = std::min<uint16_t>(256, std::min<uint16_t>(cfg.fsc, cfg.pcd_max_frame_rx));
    if (max_chunk_len == 0) {
        max_chunk_len = 16;
    }
    DESFireFileSystem dfs{_isoDEP};

    std::vector<desfire_aid_t> aids;
    if (!dfs.getApplicationIDs(aids)) {
        M5_LIB_LOGE("getApplicationIDs failed");
        return false;
    }

    for (const auto& aid : aids) {
        // App
        if (!dfs.selectApplication(aid)) {
            M5_LIB_LOGW("selectApplication failed %X", aid.aid24());
            continue;
        }
        printf("AID %02X%02X%02X ", aid.aid[0], aid.aid[1], aid.aid[2]);

        dfs.authenticateDES(0, type4::DESFIRE_DEFAULT_KEY);

        uint8_t key_settings{};
        uint8_t key_count{};
        if (dfs.getKeySettings(key_settings, key_count)) {
            printf("key_settings:%02X key_count:%u", key_settings, key_count);
        }
        putchar('\n');

        // Files
        std::vector<uint8_t> file_nos;
        if (!dfs.getFileIDs(file_nos)) {
            M5_LIB_LOGW("  getFileIDs failed");
            continue;
        }

        printf("files:%zu\n", file_nos.size());

        uint32_t idx{};
        for (const auto file_no : file_nos) {
            ++idx;
            FileSettings settings{};
            if (!dfs.getFileSettings(settings, file_no)) {
                M5_LIB_LOGW("getFileSettings failed file_no %u", file_no);
                continue;
            }
            printf("---- [%02u]:file_no %u type=%u comm=%u ar=%04X size=%u\n", idx - 1, file_no, settings.file_type,
                   settings.comm_mode, settings.access_rights, settings.file_size);
            if (settings.file_size == 0) {
                continue;
            }
            {
                const int8_t read_key = required_read_key_no_from_access_rights(settings.access_rights);
                if (read_key == kAccessDenied) {
                    M5_LIB_LOGW("dump_desfire: read access denied file_no %u", file_no);
                    continue;
                }
                if (read_key >= 0) {
                    constexpr uint8_t kDefaultKey[16]{};
                    if (!dfs.authenticateAES(static_cast<uint8_t>(read_key), kDefaultKey)) {
                        M5_LIB_LOGW("dump_desfire: authenticateAES failed key_no %d file_no %u", read_key, file_no);
                        continue;
                    }
                }
            }

            uint32_t offset = 0;
            uint32_t total  = 0;
            std::vector<uint8_t> data{};
            while (offset < settings.file_size) {
                const uint32_t remain = settings.file_size - offset;
                const uint16_t len    = static_cast<uint16_t>(std::min<uint32_t>(remain, max_chunk_len));
                std::vector<uint8_t> chunk;
                if (!dfs.readData(chunk, file_no, offset, len)) {
                    if (offset == 0) {
                        M5_LIB_LOGW("readData failed");
                    }
                    break;
                }
                if (chunk.empty()) {
                    break;
                }
                offset += chunk.size();
                total += chunk.size();
                data.insert(data.end(), chunk.begin(), chunk.end());
                if (chunk.size() < len) {
                    break;
                }
            }
            m5::utility::log::dump(data.data(), data.size(), false);
        }
    }
    return true;
}

bool NFCLayerA::dump_desfire_light()
{
    const auto cfg         = _isoDEP.config();
    uint16_t max_chunk_len = std::min<uint16_t>(16, std::min<uint16_t>(cfg.fsc, cfg.pcd_max_frame_rx));
    if (max_chunk_len == 0) {
        max_chunk_len = 16;
    }

    DESFireFileSystem dfs{_isoDEP};
    // Light default or NDEF
    if (!dfs.selectDfNameAuto(type4::DESFIRE_LIGHT_DF_NAME, sizeof(type4::DESFIRE_LIGHT_DF_NAME)) &&
        !dfs.selectDfNameAuto(type4::NDEF_AID, sizeof(type4::NDEF_AID))) {
        M5_LIB_LOGE("selectDFname failed");
        return false;
    }

    std::vector<uint8_t> file_nos;
    if (!dfs.getFileIDs(file_nos)) {
        M5_LIB_LOGW("getFileIDs failed");
        return false;
    }
    printf("files:%zu\n", file_nos.size());

    desfire::Ev2Context ctx{};
    uint32_t idx{};
    for (const auto file_no : file_nos) {
        ++idx;

#if 0        
        if (file_no == 0x0F /*TMAC*/) {
            printf("---- [%02u]:file_no %u Probably TMAC, so it can't be read\n", idx - 1, file_no);
            continue;
        }
#endif

        // For clear auth status
        if (!dfs.selectDfNameAuto(type4::DESFIRE_LIGHT_DF_NAME, sizeof(type4::DESFIRE_LIGHT_DF_NAME)) &&
            !dfs.selectDfNameAuto(type4::NDEF_AID, sizeof(type4::NDEF_AID))) {
            M5_LIB_LOGE("selectDFname failed");
            return false;
        }

        // Get fileSeetings
        FileSettings settings{};
        if (!dfs.getFileSettings(settings, file_no)) {
            if (!dfs.authenticateEV2First(0x00 /* key 0*/, type4::DESFIRE_DEFAULT_KEY, ctx) ||
                (!dfs.getFileSettingsEV2Full(settings, file_no, ctx) &&
                 !dfs.getFileSettingsEV2(settings, file_no, ctx))) {
                M5_LIB_LOGW("getFileSettings failed file_no [%02u]:%u", idx - 1, file_no);
                continue;
            }
        }
        const int8_t read_key = required_read_key_no_from_access_rights(settings.access_rights);
        if (read_key == kAccessDenied) {
            printf("read access denied file_no %u\n", file_no);
            continue;
        }
        if (read_key >= 0 || settings.comm_mode != 0) {
            ctx = {};
            if (!dfs.authenticateEV2First(static_cast<uint8_t>(read_key), type4::DESFIRE_DEFAULT_KEY, ctx)) {
                M5_LIB_LOGW("authenticateEV2First failed key_no %d file_no %u", read_key, file_no);
            }
        }

        switch (settings.file_type) {
            case 0x02:  // Value file
                printf("---- [%02u]:file_no %u Value file, so it can't be read\n", idx - 1, file_no);
                continue;
                break;
            case 0x04:  // CyclicRecord file
                printf("---- [%02u]:file_no %u CyclicRecord file, so it can't be read\n", idx - 1, file_no);
                continue;
                break;
            case 0x05:  // TMAC file
                printf("---- [%02u]:file_no %u TMAC, so it can't be read\n", idx - 1, file_no);
                continue;
                break;
            default:
                printf("---- [%02u]:file_no %u type=%u comm=%u ar=%04X size=%u\n", idx - 1, file_no, settings.file_type,
                       settings.comm_mode, settings.access_rights, settings.file_size);
                break;
        }

        uint32_t offset{}, total{};
        std::vector<uint8_t> data{};
        while (offset < settings.file_size) {
            const uint32_t remain = settings.file_size - offset;
            const uint16_t len    = static_cast<uint16_t>(std::min<uint32_t>(remain, max_chunk_len));
            std::vector<uint8_t> chunk;
            bool ok{};
            switch (settings.comm_mode) {
                case 0:
                    ok = dfs.readDataLight(chunk, file_no, offset, len);
                    break;
                case 1:
                    ok = dfs.readDataLightEV2(chunk, file_no, offset, len, ctx);
                    break;
                case 3:
                    ok = dfs.readDataLightEV2Full(chunk, file_no, offset, len, ctx);
                    break;
                default:
                    break;
            }
            if (!ok || chunk.empty()) {
                break;
            }
            offset += chunk.size();
            total += chunk.size();
            data.insert(data.end(), chunk.begin(), chunk.end());
            if (chunk.size() < len) {
                break;
            }
        }
        m5::utility::log::dump(data.data(), data.size(), false);
    }

    return true;
}

bool NFCLayerA::dump_mifare_plus_sl3(const m5::nfc::a::mifare::plus::AESKey& key)
{
    const uint16_t sectors = get_number_of_sectors(_activePICC.type);
    if (!sectors) {
        return false;
    }
    puts(dump_sector_header);

    bool ret{true};
    for (uint_fast16_t sector = 0; sector < sectors; ++sector) {
        const uint16_t key_no = mifare_plus_key_no((uint8_t)sector, false);
        if (mifare_plus_authenticateAES(key_no, key)) {
            if (!dump_sector_mifare_plus_sl3(sector)) {
                M5_LIB_LOGD("Failed to dump:%u", sector);
                return false;
            }
        } else {
            M5_LIB_LOGE("SL3 auth failed sector %u key_no %04X", sector, key_no);
            return false;
        }
    }
    return ret;
}

bool NFCLayerA::dump_sector_mifare_plus_sl3(const uint8_t sector)
{
    // Sector 0~31 has 4 blocks, 32-39 has 16 blocks (4K)
    const uint8_t blocks         = (sector < 32) ? 4U : 16U;
    const uint16_t base          = (sector < 32) ? sector * blocks : 128U + (sector - 32) * blocks;
    const uint16_t trailer_block = base + blocks - 1;
    uint8_t permissions[4]{};                 // [3] is sector trailer
    const uint8_t saddr = base + blocks - 1;  //  sector traler

    uint8_t trailer[16]{};
    std::vector<uint8_t> data;
    if (!mifare_plus_read_mac_l4(trailer_block, 1, data, false) || data.size() < sizeof(trailer)) {
        M5_LIB_LOGE("SL3 read failed trailer block %u", trailer_block);
        return false;
    }
    memcpy(trailer, data.data(), sizeof(trailer));

    bool error = !decode_access_bits(permissions, trailer + 6 /* Access bits offset */);

    // Data
    for (int_fast8_t i = 0; i < blocks - 1; ++i) {
        std::vector<uint8_t> data;
        uint8_t daddr = base + i;
        if (!mifare_plus_read_mac_l4(daddr, 1, data, false) || data.size() < 16) {
            M5_LIB_LOGE("SL3 read failed block %u", daddr);
            return false;
        }

        const uint8_t poffset      = (blocks == 4) ? i : i / 5;
        const uint8_t permission   = permissions[poffset];
        const bool show_permission = (blocks == 4) ? true : (i % 5) == 0;
        print_block(data.data(), base + i, (i == 0) ? sector : -1, show_permission ? permission : 0xFF, error,
                    can_value_block_permission(permission));
    }
    // Sector trailer
    print_block(trailer, saddr, -1, permissions[3], error);

    return true;
}

#if 0    
    for (uint16_t sector = 0; sector < sectors; ++sector) {
        const uint16_t key_no = mifare_plus_key_no((uint8_t)sector, false);
        if (!mifare_plus_authenticateAES(key_no, key)) {
            M5_LIB_LOGE("SL3 auth failed sector %u key_no %04X", sector, key_no);
            return false;
        }

        const uint8_t blocks         = (sector < 32) ? 4U : 16U;
        const uint16_t base_block    = (sector < 32) ? sector * blocks : 128U + (sector - 32) * blocks;
        const uint16_t trailer_block = base_block + blocks - 1;

        uint8_t trailer[16]{};
        std::vector<uint8_t> data;
        if (!mifare_plus_read_mac_l4(trailer_block, 1, data, false) || data.size() < sizeof(trailer)) {
            M5_LIB_LOGE("SL3 read failed trailer block %u", trailer_block);
            return false;
        }
        memcpy(trailer, data.data(), sizeof(trailer));

        uint8_t permissions[4]{};
        const bool ab_error = !decode_access_bits(permissions, trailer + 6);

        for (uint8_t i = 0; i < blocks - 1; ++i) {
            const uint16_t block = base_block + i;
            data.clear();
            if (!mifare_plus_read_mac_l4(block, 1, data, false) || data.size() < 16) {
                M5_LIB_LOGE("SL3 read failed block %u", block);
                return false;
            }
            const uint8_t poffset      = (blocks == 4) ? i : i / 5;
            const uint8_t permission   = permissions[poffset];
            const bool show_permission = (blocks == 4) ? true : (i % 5) == 0;
            print_block(data.data(), block, (i == 0) ? sector : -1, show_permission ? permission : 0xFF, ab_error,
                        can_value_block_permission(permission));
        }

        print_block(trailer, trailer_block, -1, permissions[3], ab_error);
    }

    return true;
}
#endif

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

// for NDEF
bool NFCLayerA::read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr)
{
    if (!rx || !rx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.canFastRead() ? read_using_fast(rx, rx_len, saddr)
                                     : read_using_read16(rx, rx_len, saddr, DEFAULT_KEY);
}

// for NDEF
bool NFCLayerA::write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }
    return _activePICC.supportsNFC() ? write_using_write4(saddr, tx, tx_len)
                                     : write_using_write16(saddr, tx, tx_len, DEFAULT_KEY);
}

//
bool NFCLayerA::mifare_ultralightC_authenticate1(uint8_t ek[8])
{
    uint8_t cmd[2] = {m5::stl::to_underlying(Command::AUTHENTICATE_1), 0x00};
    uint8_t rx[9]{};
    uint16_t rx_len{9};
    if (ek && _impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_AUTH1) && rx_len == 9 && rx[0] == 0xAF) {
        memcpy(ek, rx + 1, 8);
        return true;
    }
    // m5::utility::log::dump(rx, rx_len, false);
    return false;
}

bool NFCLayerA::mifare_ultralightC_authenticate2(uint8_t rx_ek[8], const uint8_t tx_ek[16])
{
    if (!rx_ek || !tx_ek) {
        return false;
    }

    uint8_t cmd[1 + 16] = {m5::stl::to_underlying(Command::AUTHENTICATE_2)};
    memcpy(cmd + 1, tx_ek, 16);

    uint8_t rx[9]{};
    uint16_t rx_len{9};
    if (_impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_AUTH2) && rx_len == 9 && rx[0] == 0x00) {
        memcpy(rx_ek, rx + 1, 8);
        return true;
    }
    return false;
}

bool NFCLayerA::nfca_deselect()
{
    uint8_t rx[1]{};
    uint16_t rx_len = sizeof(rx);
    uint8_t cmd[1]  = {m5::stl::to_underlying(Command::DESELECT)};
    if (!_impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_DESELECT) || !rx_len) {
        M5_LIB_LOGE("Failed to deselect %u", rx_len);
        return false;
    }
    // Discard response
    return true;
}

bool NFCLayerA::nfca_request_ats(m5::nfc::a::ATS& ats, const uint8_t fsdi, const uint8_t cid)
{
    if (fsdi > 8) {
        return false;
    }

    uint8_t rx[256]{};  // 2^((fsdi+4)/2) max fsdi = 8 ==> 256
    uint16_t rx_len = sizeof(rx);
    uint8_t cmd[]   = {m5::stl::to_underlying(Command::RATS), 0x00};
    cmd[1]          = ((fsdi & 0x0F) << 4) | (cid & 0x0F);

    if (!_impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_RATS) || rx_len < 2) {
        M5_LIB_LOGE("Failed to RATS %u", rx_len);
        // M5_DUMPE(cmd, sizeof(cmd));
        // m5::utility::log::dump(rx, rx_len, false);
        return false;
    }
    M5_LIB_LOGV("ATS len:%u T0:%02X TA:%02X TB:%02X TC:%02X", rx_len, rx[1], rx_len > 2 ? rx[2] : 0,
                rx_len > 3 ? rx[3] : 0, rx_len > 4 ? rx[4] : 0);

    // M5_LIB_LOGE(">>>>ATS %u bytes", rx_len);
    // m5::utility::log::dump(rx, rx_len, false);

    const uint32_t ats_len = rx[0];
    uint32_t offset{};
    ats.TL = rx[offset++];
    ats.T0 = rx[offset++];
    if (offset < ats_len && ats.validTA()) {
        ats.TA = rx[offset++];
    }
    if (offset < ats_len && ats.validTB()) {
        ats.TB = rx[offset++];
    }
    if (offset < ats_len && ats.validTC()) {
        ats.TC = rx[offset++];
    }
    ats.historical_len = 0;
    if (offset < ats_len) {
        const uint32_t hlen = std::min<uint32_t>(ats.historical.size(), ats_len - offset);
        memcpy(ats.historical.data(), rx + offset, hlen);
        ats.historical_len = hlen;
    }
    // Reflect ATS into ISO-DEP config (FSC/FWT/CID)
    {
        auto cfg           = _isoDEP.config();
        const uint16_t fsc = m5::nfc::isodep::fsci_to_fsc(ats.fsci());
        if (fsc) {
            cfg.fsc = fsc;
        }
        const uint8_t fwi     = ats.validTB() ? ats.fwi() : 4;  // Default FWI=4 if TB absent
        const uint32_t fwt_ms = m5::nfc::isodep::fwi_to_ms(fwi, 13.56e6f);
        if (fwt_ms) {
            cfg.fwt_ms = fwt_ms;
        }
        cfg.use_cid = (cid != 0) && ats.supportsCID();
        cfg.cid     = cid & 0x0F;
        _isoDEP.config(cfg);
        M5_LIB_LOGE("ISO-DEP cfg: FSCI:%u FSC:%u FWT:%u CID:%u tx:%u rx:%u", ats.fsci(), cfg.fsc, cfg.fwt_ms,
                    cfg.use_cid, cfg.pcd_max_frame_tx, cfg.pcd_max_frame_rx);
    }

    return true;
}

bool NFCLayerA::mifare_get_version_L3(uint8_t ver[8])
{
    if (!ver) {  // Skip check valid (Since it targets unconfirmed items)
        return false;
    }
    // GetVerison (L3)
    uint8_t cmd[1]  = {m5::stl::to_underlying(Command::GET_VERSION)};
    uint16_t rx_len = 8;
    return _impl->transceive(ver, rx_len, cmd, sizeof(cmd), TIMEOUT_GET_VERSION);
}

bool NFCLayerA::mifare_get_version_L4_wrapped(uint8_t* ver, uint16_t& ver_len)
{
    auto org_ver_len = ver_len;
    ver_len          = 0;

    if (!ver || org_ver_len < 8) {  // Skip check valid (Since it targets unconfirmed items)
        return false;
    }

    // GetVerison (L4) Native wrappe command style like APDU
    uint8_t cmd[] = {0x90, m5::stl::to_underlying(Command::GET_VERSION), 0x00, 0x00, 0x00};
    uint8_t rx[128]{};
    uint16_t rx_len = sizeof(rx);

    // auto cfg         = _isoDEP.config();
    //     const auto saved = cfg.fwt_ms;
    //     cfg.fwt_ms       = TIMEOUT_GET_VERSION;
    // cfg.rx_crc       = true;
    //_isoDEP.config(cfg);

    std::vector<uint8_t> acc{};
    acc.reserve(org_ver_len);

    if (!_isoDEP.transceiveINF(rx, rx_len, cmd, sizeof(cmd)) || (rx_len < 2)) {
        M5_LIB_LOGD("Failed to GetVersionL4 %u", rx_len);
        // cfg.fwt_ms = saved;
        //_isoDEP.config(cfg);
        return false;
    }
    acc.insert(acc.end(), rx, rx + rx_len);

    // M5_LIB_LOGE(">>>> 1st");
    // m5::utility::log::dump(rx, rx_len, false);

    constexpr uint8_t MAX_AF_FOLLOW{32};
    constexpr uint8_t cmd_af[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    uint8_t af_follow{};
    while (rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0xAF) {
        if (++af_follow > MAX_AF_FOLLOW) {
            break;
        }
        // More response please!
        rx_len = sizeof(rx);
        if (!_isoDEP.transceiveINF(rx, rx_len, cmd_af, sizeof(cmd_af)) || (rx_len < 2)) {
            break;
        }

        acc.insert(acc.end(), rx, rx + rx_len);
        if (acc.size() > org_ver_len) {
            break;
        }
    }
    // cfg.fwt_ms = saved;
    //_isoDEP.config(cfg);

    if (rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0x00) {
        ver_len = std::min<uint16_t>(org_ver_len, acc.size());
        std::memcpy(ver, acc.data(), ver_len);
        return true;
    }
    return false;
}

bool NFCLayerA::mifare_get_version_L4_raw(uint8_t* ver, uint16_t& ver_len)
{
    auto org_ver_len = ver_len;
    ver_len          = 0;

    if (!ver || org_ver_len < 8) {  // Skip check valid (Since it targets unconfirmed items)
        return false;
    }

    // GetVersion (L4) raw ISO-DEP (native command)
    uint8_t cmd[] = {m5::stl::to_underlying(Command::GET_VERSION)};
    uint8_t rx[128]{};
    uint16_t rx_len = sizeof(rx);

    // auto cfg         = _isoDEP.config();
    // const auto saved = cfg.fwt_ms;
    // cfg.fwt_ms       = TIMEOUT_GET_VERSION;
    // cfg.rx_crc       = true;
    //_isoDEP.config(cfg);

    std::vector<uint8_t> acc{};
    acc.reserve(org_ver_len);

    if (!_isoDEP.transceiveINF(rx, rx_len, cmd, sizeof(cmd)) || (rx_len < 1)) {
        M5_LIB_LOGD("Failed to GetVersionL4 %u", rx_len);
        // cfg.fwt_ms = saved;
        //_isoDEP.config(cfg);
        return false;
    }

    constexpr uint8_t MAX_AF_FOLLOW{32};
    uint8_t af_follow{};
    while (true) {
        if (rx_len < 1) {
            break;
        }
        // M5_LIB_LOGE("GetVersion L4 raw rx_len=%u", rx_len);
        // M5_DUMPE(rx, rx_len);

        // Some Plus SL1 cards return status at head: [AF|00] + payload.
        const bool status_head = (rx_len >= 2) && ((rx[0] == 0xAF) || (rx[0] == 0x00));
        uint8_t status         = status_head ? rx[0] : rx[rx_len - 1];
        const uint8_t* payload = status_head ? (rx + 1) : rx;
        uint16_t pay_len       = status_head ? (rx_len - 1) : ((rx_len > 1) ? (rx_len - 1) : 0);
        // Some cards return 90 00 at head with payload after it.
        if (!status_head && rx_len >= 2 && rx[0] == 0x90 && rx[1] == 0x00) {
            status  = 0x00;
            payload = rx + 2;
            pay_len = rx_len - 2;
        }
        // Some cards append ISO7816-style status (90 00) at tail, strip it.
        if (pay_len >= 2 && payload[pay_len - 2] == 0x90 && payload[pay_len - 1] == 0x00) {
            pay_len -= 2;
        }

        if (pay_len > 0) {
            acc.insert(acc.end(), payload, payload + pay_len);
        }
        if (status != 0xAF) {
            break;
        }
        if (++af_follow > MAX_AF_FOLLOW) {
            break;
        }
        // More response please!
        const uint8_t cmd_af[] = {0xAF};
        rx_len                 = sizeof(rx);
        if (!_isoDEP.transceiveINF(rx, rx_len, cmd_af, sizeof(cmd_af)) || (rx_len < 1)) {
            break;
        }
        if (acc.size() > org_ver_len) {
            break;
        }
    }
    // cfg.fwt_ms = saved;
    //_isoDEP.config(cfg);

    if (acc.size() > org_ver_len) {
        acc.resize(org_ver_len);
    }
    ver_len = acc.size();
    std::memcpy(ver, acc.data(), ver_len);

    // M5_LIB_LOGE("VERL4-====");
    // M5_DUMPE(acc.data(), acc.size());

    return ver_len >= 6;
}

bool NFCLayerA::mifare_plus_authenticateAES(const uint16_t key_no, const mifare::plus::AESKey& key)
{
    uint8_t rx[256]{};
    uint16_t rx_len{};

    // Step 1: 0x70 KeyNo LSB/MSB 0x00
    uint8_t cmd1[] = {0x70, (uint8_t)(key_no & 0xFF), (uint8_t)(key_no >> 8), 0x00};
    rx_len         = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, cmd1, sizeof(cmd1)) || rx_len < 1) {
        M5_LIB_LOGE("AuthAES step1 transceive failed");
        return false;
    }
    if ((rx[0] != 0x90 && rx[0] != 0xAF) || rx_len < 17) {
        M5_LIB_LOGE("AuthAES step1 invalid response len=%u st=%02X", rx_len, rx[0]);
        m5::utility::log::dump(rx, rx_len, false);
        return false;
    }

    const bool step1_has_status  = (rx[0] == 0x90 || rx[0] == 0xAF);
    const uint8_t* step1_payload = step1_has_status ? rx + 1 : rx;
    size_t step1_len             = step1_has_status ? (rx_len - 1) : rx_len;
    if (step1_len >= 2 && step1_payload[step1_len - 2] == 0x90 && step1_payload[step1_len - 1] == 0x00) {
        step1_len -= 2;
    }
    if (step1_len < 16) {
        M5_LIB_LOGE("AuthAES step1 payload too short len=%u", (unsigned)step1_len);
        return false;
    }

    uint8_t rndB[16]{};
    {
        uint8_t iv[16]{};
        mbedtls_aes_context aes{};
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(rndB), iv, step1_payload, rndB);
        mbedtls_aes_free(&aes);
    }

    uint8_t rndA[16]{};
    for (auto& b : rndA) {
        b = (uint8_t)(esp_random() & 0xFF);
    }

    uint8_t rndB_rot[16]{};
    memcpy(rndB_rot, rndB + 1, 15);
    rndB_rot[15] = rndB[0];

    uint8_t ab_plain[32]{};
    memcpy(ab_plain, rndA, 16);
    memcpy(ab_plain + 16, rndB_rot, 16);

    uint8_t cmd2[33]{};
    cmd2[0] = 0x72;
    {
        uint8_t iv[16]{};
        mbedtls_aes_context aes{};
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(ab_plain), iv, ab_plain, cmd2 + 1);
        mbedtls_aes_free(&aes);
    }

    rx_len = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, cmd2, sizeof(cmd2)) || rx_len < 1) {
        M5_LIB_LOGE("AuthAES step2 transceive failed");
        return false;
    }
    if ((rx[0] != 0x90 && rx[0] != 0xAF) || rx_len < 33) {
        M5_LIB_LOGE("AuthAES step2 invalid response len=%u st=%02X", rx_len, rx[0]);
        m5::utility::log::dump(rx, rx_len, false);
        return false;
    }

    const bool step2_has_status  = (rx[0] == 0x90 || rx[0] == 0xAF);
    const uint8_t* step2_payload = step2_has_status ? rx + 1 : rx;
    size_t step2_len             = step2_has_status ? (rx_len - 1) : rx_len;
    if (step2_len >= 2 && step2_payload[step2_len - 2] == 0x90 && step2_payload[step2_len - 1] == 0x00) {
        step2_len -= 2;
    }
    if (step2_len < 32) {
        M5_LIB_LOGE("AuthAES step2 payload too short len=%u", (unsigned)step2_len);
        return false;
    }

    uint8_t ab_resp[32]{};
    {
        uint8_t iv[16]{};
        mbedtls_aes_context aes{};
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, sizeof(ab_resp), iv, step2_payload, ab_resp);
        mbedtls_aes_free(&aes);
    }

    uint8_t rndA_rot[16]{};
    memcpy(rndA_rot, rndA + 1, 15);
    rndA_rot[15] = rndA[0];
    if (memcmp(ab_resp + 4, rndA_rot, 16) != 0) {
        M5_LIB_LOGE("AuthAES rndA mismatch");
        return false;
    }
    uint8_t kenc[16]{};
    memcpy(kenc, rndA + 11, 5);
    memcpy(kenc + 5, rndB + 11, 5);
    for (int i = 0; i < 5; ++i) {
        kenc[10 + i] = rndA[4 + i] ^ rndB[4 + i];
    }
    kenc[15] = 0x11;

    uint8_t kmac[16]{};
    memcpy(kmac, rndA + 7, 5);
    memcpy(kmac + 5, rndB + 7, 5);
    for (int i = 0; i < 5; ++i) {
        kmac[10 + i] = rndA[i] ^ rndB[i];
    }
    kmac[15] = 0x22;

    {
        uint8_t iv[16]{};
        mbedtls_aes_context aes{};
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key.data(), 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(kenc), iv, kenc, kenc);
        memset(iv, 0, sizeof(iv));
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(kmac), iv, kmac, kmac);
        mbedtls_aes_free(&aes);
    }

    _mfp_session.authenticated = true;
    _mfp_session.key_no        = key_no;
    _mfp_session.r_ctr         = 0;
    _mfp_session.w_ctr         = 0;
    _mfp_session.frame_num     = 0;
    memcpy(_mfp_session.ti.data(), ab_resp, 4);
    memcpy(_mfp_session.kenc.data(), kenc, sizeof(kenc));
    memcpy(_mfp_session.kmac.data(), kmac, sizeof(kmac));

#if 0    
    M5_LIB_LOGE("session: key_no=%04X rctr=%u wctr=%u ti=%02X%02X%02X%02X", _mfp_session.key_no, _mfp_session.r_ctr,
                _mfp_session.w_ctr, _mfp_session.ti[0], _mfp_session.ti[1], _mfp_session.ti[2], _mfp_session.ti[3]);
    M5_LIB_LOGE("session: kenc:");
    m5::utility::log::dump(_mfp_session.kenc.data(), _mfp_session.kenc.size(), false);
    M5_LIB_LOGE("session: kmac:");
    m5::utility::log::dump(_mfp_session.kmac.data(), _mfp_session.kmac.size(), false);
#endif
    return true;
}

bool NFCLayerA::mifare_plus_transceive_raw(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || !_activePICC.valid()) {
        return false;
    }
    constexpr uint32_t timeout_mfp_raw = 100;
    return _impl->transceive(rx, rx_len, tx, tx_len, timeout_mfp_raw);
}

bool NFCLayerA::mifare_plus_read_plain_nomac(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out)
{
    out.clear();
    if (count == 0 || count > 3) {
        return false;
    }
    uint8_t tx[] = {0x36, (uint8_t)(block & 0xFF), (uint8_t)((block >> 8) & 0xFF), count};
    uint8_t rx[64]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, tx, sizeof(tx)) || rx_len < 1) {
        return false;
    }

    const bool has_status  = (rx[0] == 0x90 || rx[0] == 0xAF);
    const uint8_t* payload = has_status ? rx + 1 : rx;
    size_t pay_len         = has_status ? (rx_len - 1) : rx_len;
    if (pay_len >= 2 && payload[pay_len - 2] == 0x90 && payload[pay_len - 1] == 0x00) {
        pay_len -= 2;
    }
    if (pay_len < static_cast<size_t>(count) * 16) {
        return false;
    }
    out.insert(out.end(), payload, payload + (size_t)count * 16);
    return true;
}

bool NFCLayerA::mifare_plus_read_plain_mac(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out)
{
    out.clear();
    if (!_mfp_session.authenticated || count == 0 || count > 3 || block > 0xFF) {
        return false;
    }

    const uint16_t r_ctr = _mfp_session.r_ctr;
    const uint16_t w_ctr = _mfp_session.w_ctr;

    const bool plain    = false;
    const bool nomaccmd = false;
    const bool nomacres = false;
    uint8_t cmd         = 0x31;
    if (nomacres) {
        cmd ^= 0x01;
    }
    if (plain) {
        cmd ^= 0x02;
    }
    if (nomaccmd) {
        cmd ^= 0x04;
    }

    uint8_t rcmd1[4] = {cmd, (uint8_t)(block & 0xFF), 0x00, count};
    uint8_t mac[8]{};
    if (!nomaccmd) {
        if (!mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, w_ctr,
                                       MfpMacType::ReadCmd, (uint8_t)block, count, rcmd1, sizeof(rcmd1), mac)) {
            return false;
        }
    }

    uint8_t tx[12]{};
    memcpy(tx, rcmd1, sizeof(rcmd1));
    if (!nomaccmd) {
        memcpy(tx + sizeof(rcmd1), mac, sizeof(mac));
    }
    M5_LIB_LOGE("read cmd:");
    m5::utility::log::dump(tx, nomaccmd ? sizeof(rcmd1) : sizeof(tx), false);

    uint8_t rx[128]{};
    const size_t data_len = (size_t)count * 16;
    uint16_t rx_len       = sizeof(rx);
    const uint16_t tx_len = nomaccmd ? sizeof(rcmd1) : sizeof(tx);
    if (!mifare_plus_transceive_raw(rx, rx_len, tx, tx_len) || rx_len < 1) {
        M5_LIB_LOGE("read transceive failed len=%u", rx_len);
        return false;
    }
    if (rx[0] != 0x90) {
        M5_LIB_LOGE("read status error len=%u st=%02X", rx_len, rx[0]);
        m5::utility::log::dump(rx, rx_len, false);
        return false;
    }

    if (rx_len < 1 + data_len) {
        return false;
    }

    size_t status_len = 0;
    if (rx_len >= 1 + data_len + 2 && rx[rx_len - 2] == 0x90 && rx[rx_len - 1] == 0x00) {
        status_len = 2;
    }
    size_t mac_len = 0;
    if (!nomacres && rx_len >= 1 + data_len + status_len + 8) {
        mac_len = 8;
    }

    if (mac_len == 8) {
        uint8_t mac_resp[8]{};
        const uint16_t resp_ctr = r_ctr + 1;
        mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), resp_ctr, w_ctr,
                                  MfpMacType::ReadResp, (uint8_t)block, count, rx, 1 + data_len, mac_resp);
        if (memcmp(rx + 1 + data_len, mac_resp, sizeof(mac_resp)) != 0) {
            M5_LIB_LOGW("mac mismatch");
        }
    }

    std::vector<uint8_t> payload(rx + 1, rx + 1 + data_len);
    if (!plain) {
        mbedtls_aes_context aes{};
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, _mfp_session.kenc.data(), 128);
        for (uint8_t i = 0; i < count; ++i) {
            uint8_t iv[16]{};
            const uint8_t ctr = (uint8_t)(r_ctr & 0xFF);
            iv[0]             = ctr;
            iv[4]             = ctr;
            iv[8]             = ctr;
            memcpy(&iv[12], _mfp_session.ti.data(), 4);
            uint8_t* blk = payload.data() + i * 16;
            mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, blk, blk);
        }
        mbedtls_aes_free(&aes);
    }

    out.insert(out.end(), payload.begin(), payload.end());
    _mfp_session.r_ctr = r_ctr + 1;
    return true;
}

#if 0
bool NFCLayerA::mifare_plus_read_plain_mac_l4(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out)
{
    out.clear();
    if (!_mfp_session.authenticated || count == 0 || count > 3 || block > 0xFF) {
        return false;
    }

    const uint16_t r_ctr = _mfp_session.r_ctr;
    const uint16_t w_ctr = _mfp_session.w_ctr;

    const uint8_t cmd = 0x33;  // ReadPlainMAC_MACed
    uint8_t rcmd1[4]  = {cmd, (uint8_t)(block & 0xFF), 0x00, count};
    uint8_t mac[8]{};
    if (!mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, w_ctr, MfpMacType::ReadCmd,
                                   (uint8_t)block, count, rcmd1, sizeof(rcmd1), mac)) {
        return false;
    }

    uint8_t tx[12]{};
    memcpy(tx, rcmd1, sizeof(rcmd1));
    memcpy(tx + sizeof(rcmd1), mac, sizeof(mac));

    uint8_t rx[128]{};
    const size_t data_len = (size_t)count * 16;
    uint16_t rx_len       = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, tx, sizeof(tx)) || rx_len < 1) {
        return false;
    }

    // M5_LIB_LOGE("RX:>>>");
    // M5_DUMPE(rx,rx_len);

    if (rx[0] != 0x90) {
        return false;
    }
    if (rx_len < 1 + data_len) {
        return false;
    }

    size_t status_len = 0;
    if (rx_len >= 1 + data_len + 2 && rx[rx_len - 2] == 0x90 && rx[rx_len - 1] == 0x00) {
        status_len = 2;
    }
    if (rx_len < 1 + data_len + status_len + 8) {
        return false;
    }

    uint8_t mac_resp[8]{};
    const uint16_t resp_ctr = r_ctr + 1;
    mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), resp_ctr, w_ctr, MfpMacType::ReadResp,
                              (uint8_t)block, count, rx, 1 + data_len, mac_resp);
    if (memcmp(rx + 1 + data_len, mac_resp, sizeof(mac_resp)) != 0) {
        M5_LIB_LOGW("SL3 mac mismatch");
    }

    out.insert(out.end(), rx + 1, rx + 1 + data_len);
    _mfp_session.r_ctr++;
    return true;
}

bool NFCLayerA::mifare_plus_write_plain_mac_l4(const uint16_t block, const uint8_t* data, const uint16_t data_len)
{
    if (!data || data_len == 0 || !_mfp_session.authenticated || block > 0xFF) {
        M5_LIB_LOGE(">>>>ERROR1");
        return false;
    }
    if (data_len > 16) {
        M5_LIB_LOGE(">>>>ERROR2");
        return false;
    }

    const uint16_t r_ctr = _mfp_session.r_ctr;
    const uint16_t w_ctr = _mfp_session.w_ctr;

    uint8_t payload[16]{};
    memcpy(payload, data, std::min<uint16_t>(16, data_len));

    const uint8_t cmd            = 0xA1;  // WritePlainMAC_MACed
    uint8_t rcmd[1 + 2 + 16 + 8] = {cmd, (uint8_t)(block & 0xFF), 0x00};
    memcpy(rcmd + 3, payload, 16);

    if (!mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, w_ctr, MfpMacType::WriteCmd,
                                   (uint8_t)block, 1, rcmd, 1 + 2 + 16, rcmd + 19)) {
        M5_LIB_LOGE(">>>>ERROR3");
        return false;
    }

    uint8_t rx[32]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, rcmd, sizeof(rcmd)) || rx_len < 1) {
        M5_LIB_LOGE(">>>>ERROR4");
        return false;
    }
    if (rx[0] != 0x90) {
        M5_LIB_LOGE(">>>>ERROR5");
        M5_DUMPE(rx, rx_len);
        return false;
    }

    _mfp_session.w_ctr++;
    return true;
}
#endif

bool NFCLayerA::mifare_plus_read_mac_l4(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out,
                                        const bool plain)
{
    out.clear();
    if (!_mfp_session.authenticated || count == 0 || count > 3 || block > 0xFF) {
        return false;
    }

    const uint16_t r_ctr = _mfp_session.r_ctr;
    const uint16_t w_ctr = _mfp_session.w_ctr;

    uint8_t cmd = 0x31;
    if (plain) {
        cmd ^= 0x02;
    }

    uint8_t rcmd1[4] = {cmd, (uint8_t)(block & 0xFF), 0x00, count};
    uint8_t mac[8]{};
    if (!mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, w_ctr, MfpMacType::ReadCmd,
                                   (uint8_t)block, count, rcmd1, sizeof(rcmd1), mac)) {
        return false;
    }

    uint8_t tx[12]{};
    memcpy(tx, rcmd1, sizeof(rcmd1));
    memcpy(tx + sizeof(rcmd1), mac, sizeof(mac));

    uint8_t rx[128]{};
    const size_t data_len = (size_t)count * 16;
    uint16_t rx_len       = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, tx, sizeof(tx))) {
        return false;
    }

    if (rx[0] != 0x90 && rx[0] != 0xAF) {
        return false;
    }
    const bool has_trailer   = (rx_len >= data_len + 8 + 2) && rx[rx_len - 2] == 0x90 && rx[rx_len - 1] == 0x00;
    const size_t payload_len = has_trailer ? (rx_len - 1 - 8 - 2) : (rx_len - 1 - 8);
    if (payload_len < data_len) {
        return false;
    }
    const uint8_t* payload = rx + 1;
    const uint8_t* mac_rx  = payload + payload_len;

    _mfp_session.r_ctr++;
    const uint16_t resp_ctr = _mfp_session.r_ctr;
    uint8_t mac_resp[8]{};
    const size_t mac_len = rx_len - 8 - (has_trailer ? 2 : 0);
    mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), resp_ctr, w_ctr, MfpMacType::ReadResp,
                              (uint8_t)block, count, rx, mac_len, mac_resp);
    if (memcmp(mac_rx, mac_resp, sizeof(mac_resp)) != 0) {
        M5_LIB_LOGW("SL3 mac mismatch");
    }

    std::vector<uint8_t> payload_buf(payload, payload + data_len);
    if (!plain) {
        for (size_t offset = 0; offset < payload_buf.size(); offset += 16) {
            // CalculateEncIVResponse: [R_Ctr 2B][W_Ctr 2B] x3 [TI 4B]
            uint8_t iv[16]{};
            memcpy(&iv[0], &resp_ctr, 2);
            memcpy(&iv[2], &w_ctr, 2);
            memcpy(&iv[4], &resp_ctr, 2);
            memcpy(&iv[6], &w_ctr, 2);
            memcpy(&iv[8], &resp_ctr, 2);
            memcpy(&iv[10], &w_ctr, 2);
            memcpy(&iv[12], _mfp_session.ti.data(), 4);
            /*
            M5_LIB_LOGE("READ blk=%u r_ctr=%u w_ctr=%u", block, resp_ctr, w_ctr);
            M5_LIB_LOGE("READ IV:");
            m5::utility::log::dump(iv, 16, false);
            M5_LIB_LOGE("READ enc:");
            m5::utility::log::dump(payload_buf.data() + offset, 16, false);
            */

            mifare_plus_data_crypt_block(_mfp_session.kenc.data(), iv, payload_buf.data() + offset,
                                         payload_buf.data() + offset, true);
            /*
            M5_LIB_LOGE("READ dec:");
            m5::utility::log::dump(payload_buf.data() + offset, 16, false);
            */
        }
    }

    out.insert(out.end(), payload_buf.begin(), payload_buf.end());
    return true;
}

bool NFCLayerA::mifare_plus_write_mac_l4(const uint16_t block, const uint8_t* data, const uint16_t data_len,
                                         const bool plain)
{
    if (!data || data_len == 0 || !_mfp_session.authenticated || block > 0xFF) {
        return false;
    }
    if (data_len > 16) {
        return false;
    }

    const uint16_t r_ctr = _mfp_session.r_ctr;
    const uint16_t w_ctr = _mfp_session.w_ctr;

    uint8_t payload[16]{};
    memcpy(payload, data, std::min<uint16_t>(16, data_len));
    if (!plain) {
        uint8_t iv[16]{};
        memcpy(&iv[0], _mfp_session.ti.data(), 4);
        memcpy(&iv[4], &r_ctr, 2);
        memcpy(&iv[6], &w_ctr, 2);
        memcpy(&iv[8], &r_ctr, 2);
        memcpy(&iv[10], &w_ctr, 2);
        memcpy(&iv[12], &r_ctr, 2);
        memcpy(&iv[14], &w_ctr, 2);

        /*
        M5_LIB_LOGE("WRITE blk=%u w_ctr=%u", block, w_ctr);
        M5_LIB_LOGE("WRITE IV:");
        m5::utility::log::dump(iv, 16, false);
        M5_LIB_LOGE("WRITE plain:");
        m5::utility::log::dump(payload, 16, false);
        */

        mifare_plus_data_crypt_block(_mfp_session.kenc.data(), iv, payload, payload, false);

        /*
        M5_LIB_LOGE("WRITE enc:");
        m5::utility::log::dump(payload, 16, false);
        */
    }

    uint8_t cmd = 0xA1;
    if (plain) {
        cmd ^= 0x02;
    }

    uint8_t rcmd[1 + 2 + 16 + 8] = {cmd, (uint8_t)(block & 0xFF), 0x00};
    memcpy(rcmd + 3, payload, sizeof(payload));

    if (!mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, w_ctr, MfpMacType::WriteCmd,
                                   (uint8_t)block, 1, rcmd, 1 + 2 + 16, rcmd + 19)) {
        return false;
    }

    uint8_t rx[32]{};
    uint16_t rx_len = sizeof(rx);
    if (!_isoDEP.transceiveINF(rx, rx_len, rcmd, sizeof(rcmd)) || rx_len < 1) {
        return false;
    }
    if (rx[0] != 0x90) {
        return false;
    }

    _mfp_session.w_ctr++;
    if (rx_len >= 1 + 8) {
        const uint16_t resp_ctr = _mfp_session.w_ctr;
        uint8_t mac_resp[8]{};
        mifare_plus_calculate_mac(_mfp_session.kmac.data(), _mfp_session.ti.data(), r_ctr, resp_ctr,
                                  MfpMacType::WriteResp, (uint8_t)block, 1, rx, rx_len, mac_resp);
        if (memcmp(rx + 1, mac_resp, sizeof(mac_resp)) != 0) {
            M5_LIB_LOGW("SL3 mac mismatch");
        }
    }
    return true;
}

bool NFCLayerA::ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    if (!rx || !rx_len || spage > epage || !_activePICC.valid()) {
        return false;
    }
    uint8_t cmd[3]      = {m5::stl::to_underlying(Command::FAST_READ), spage, epage};
    const uint8_t pages = epage - spage + 1;
    uint16_t timeout    = (pages == 1)   ? TIMEOUT_FAST_READ
                          : (pages < 4)  ? TIMEOUT_FAST_READ_4PAGE
                          : (pages < 12) ? TIMEOUT_FAST_READ_12PAGE
                          : (pages < 32) ? TIMEOUT_FAST_READ_32PAGE
                                         : TIMEOUT_FAST_READ_32PAGE * 2;

    if (!_impl->transceive(rx, rx_len, cmd, sizeof(cmd), timeout)) {
        M5_LIB_LOGD("Failed to transceive");
        return false;
    }
    return true;
}

bool NFCLayerA::ntag_write_page(const uint8_t page, const uint8_t tx[4])
{
    if (!tx || !_activePICC.valid()) {
        return false;
    }

    // M5_LIB_LOGD("WRITE_PAGE:%u", page);
    // m5::utility::log::dump(tx, 4, false);
    uint8_t cmd[6]{m5::stl::to_underlying(m5::nfc::a::Command::WRITE_PAGE), page};
    std::memcpy(cmd + 2, tx, 4);

    uint8_t rx[1]{};
    uint16_t rx_len{1};
    return _impl->transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_WRITE1);
}

}  // namespace nfc
}  // namespace m5
