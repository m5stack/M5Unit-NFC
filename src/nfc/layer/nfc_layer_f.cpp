/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_f.cpp
  @brief Common layer for NFC-F
*/
#include "nfc_layer_f.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>
#include <esp_random.h>

using namespace m5::nfc::f;
using namespace m5::nfc::ndef;

namespace {

constexpr uint16_t known_system_code_table[] = {system_code_wildcard, system_code_ndef, system_code_felica_secure_id,
                                                system_code_shared,   system_code_dfc,  system_code_felica_plug};

inline bool exists_known_system_code(const uint16_t code)
{
    return std::find(std::begin(known_system_code_table), std::end(known_system_code_table), code) !=
           std::end(known_system_code_table);
}

inline bool exists_picc(const std::vector<PICC>& v, const PICC& picc)
{
    return std::find_if(v.begin(), v.end(),
                        [&picc](const PICC& p) { return p.idm == picc.idm && p.pmm == picc.pmm; }) != v.end();
}

void print_block(const uint8_t buf[16], const int16_t block)
{
    char tmp[64 + 1] = "      ";
    uint32_t left{};
    // Block
    left += snprintf(tmp + left, 12, "[%04X]:", block);
    // Data
    for (uint8_t i = 0; i < 16; ++i) {
        left += snprintf(tmp + left, 4, "%02X ", buf[i]);
    }
    ::puts(tmp);
}

inline bool is_same_idm_and_pmm(const PICC& a, const PICC& b)
{
    return a.idm == b.idm && a.pmm == b.pmm;
}

const uint8_t* make_rc(uint8_t rc[16])
{
    for (uint_fast8_t i = 0; i < 16; ++i) {
        rc[i] = esp_random();
    }
    return rc;
}

}  // namespace

namespace m5 {
namespace unit {
namespace nfc {

bool NFCLayerF::polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                        const m5::nfc::f::TimeSlot time_slot)
{
    return _impl->polling(picc, system_code, request_code, time_slot);
}

bool NFCLayerF::detect(m5::nfc::f::PICC& picc, const uint32_t timeout_ms)
{
    std::vector<PICC> piccs;
    picc = PICC{};

    if (detect(piccs, TimeSlot::Slot1, timeout_ms)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

bool NFCLayerF::detect(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t* private_code, const uint8_t pc_size,
                       m5::nfc::f::TimeSlot time_slot, const uint32_t timeout_ms)
{
    uint8_t slots = timeslot_to_slot(time_slot);

    _authenticated = false;
    piccs.clear();
    piccs.reserve(slots);

    auto timeout_at = m5::utility::millis() + timeout_ms;
    uint8_t detected{};
    do {
        PICC picc1{}, picc2{};
        Type type{};
        uint8_t format{};

        // Format identification
        // 1. Polling wildcard
        if (!polling(picc1, system_code_wildcard, RequestCode::None, time_slot)) {
            break;
        }
        // Already exists?
        if (exists_picc(piccs, picc1)) {
            continue;
        }

        M5_LIB_LOGE("detect %s", picc1.idmAsString().c_str());

        _activePICC = picc1;

        // 2. Check IDm for NFCIP-1 Transport Protocol / DFC
        if (picc1.idm[0] == 0x01 && picc1.idm[1] == 0xFE) {
            format |= format_nfcip1;
        } else if (picc1.idm[0] == 0x03 && picc1.idm[1] == 0xFE) {
            format |= format_dfc;
        }

        if ((picc1.idm[0] & 0x0F) == 0x04 && picc1.idm[1] == 0xFE) {
            type = Type::FeliCaStandard;
        }

        // 3. Check private area
        if (private_code && pc_size) {
            for (uint_fast8_t i = 0; i < pc_size; ++i) {
                auto code = private_code[i];
                if (exists_known_system_code(code)) {
                    M5_LIB_LOGW("Skip %04X (known system code)", code);
                    continue;
                }
                if (polling(picc2, code, RequestCode::None, time_slot)) {
                    if (!is_same_idm_and_pmm(picc1, picc2)) {
                        continue;
                    }
                    format |= format_private;
                }
            }
            // When private code is specified, PICC that do not meet the conditions are invalid
            if ((format & format_private) == 0) {
                continue;
            }
        }

        // 4. Check NDEF
        if (polling(picc2, system_code_ndef, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_ndef;
        }

        // 5. Check shared area
        if (polling(picc2, system_code_shared, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_shared;
        }

        // 6. Check DFC
        if (polling(picc2, system_code_dfc, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_dfc;
        }

        // 7. Check secure
        if (polling(picc2, system_code_felica_secure_id, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_secure;
        }

        // Type identification
        if (polling(picc2, system_code_felica_plug, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            type = Type::FeliCaPlug;
        } else {
            // Lite or LiteS?
            if (format & format_dfc) {
                uint8_t rbuf[16]{};
                type = read_16(rbuf, 0xA0 /* CRC_CHECK */, false) ? Type::FeliCaLiteS : Type::FeliCaLite;
                if (!read_16(rbuf, 0x82, false)) {  // Read ID(DFC format)
                    continue;
                }
                picc1.dfc_format = rbuf[8] | ((uint16_t)rbuf[9] << 8);
            }
        }

        //
        if (type == Type::Unknown) {
            M5_LIB_LOGE("Unknown: %x", format);
            if (format) {
                type = Type::FeliCaStandard;
            } else {
                continue;
            }
        }

        // Re-check
        if (type == Type::FeliCaStandard) {
            standard::Mode mode{};
            PICC tmp = picc1;
            tmp.type = Type::FeliCaStandard;
            if (!_impl->requestResponse(mode, tmp)) {
                M5_LIB_LOGE("mode error");
                continue;
            }
        }

        //
        picc1.format = format;
        picc1.type   = type;

        if (picc1.type != Type::Unknown) {
            M5_LIB_LOGV("Detected:%s", picc1.idmAsString().c_str());
            piccs.push_back(picc1);
            ++detected;
        }
        deactivate();
    } while (detected < slots && m5::utility::millis() <= timeout_at);
    deactivate();
    return detected > 0;
}

bool NFCLayerF::activate(const m5::nfc::f::PICC& picc)
{
    if (picc.valid()) {
        _activePICC    = picc;
        _authenticated = false;
        return true;
    }
    return false;
}

bool NFCLayerF::deactivate()
{
    _activePICC    = PICC{};
    _authenticated = false;
    return true;
}

bool NFCLayerF::requestService(uint16_t& key_version, const uint16_t node_code)
{
    key_version = KEY_VERIOSN_NONE;
    return requestService(&key_version, &node_code, 1);
}

bool NFCLayerF::requestService(uint16_t key_version[], const uint16_t* node_code, const uint8_t node_size)
{
    return _activePICC.valid() && _impl->requestService(key_version, _activePICC, node_code, node_size);
}

bool NFCLayerF::requestResponse(m5::nfc::f::standard::Mode& mode)
{
    return _activePICC.valid() && _impl->requestResponse(mode, _activePICC);
}

bool NFCLayerF::requestSystemCode(uint16_t code_list[255], uint8_t& code_num)
{
    return _activePICC.valid() && _impl->requestSystemCode(code_list, code_num, _activePICC);
}

bool NFCLayerF::read16(uint8_t rx[16], const m5::nfc::f::block_t block, const uint16_t service_code)
{
    return read16(rx, &block, 1, &service_code, 1);
}

bool NFCLayerF::read16(uint8_t rx[16], const m5::nfc::f::block_t* block, const uint8_t block_num,
                       const uint16_t* service_code, const uint8_t service_num)
{
    uint16_t rx_len{16};
    return rx && block && block_num && service_code && service_num && _activePICC.valid() &&
           _impl->readWithoutEncryption(rx, rx_len, _activePICC, service_code, service_num, block, block_num) &&
           rx_len == 16;
}

bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t* block, const uint8_t block_num)
{
    if (!_activePICC.valid() || !rx || !rx_len || !block || !block_num || block_num > _activePICC.maximumReadBlocks()) {
        return false;
    }

    uint16_t sc{service_random_read};
    return _impl->readWithoutEncryption(rx, rx_len, _activePICC, &sc, 1, block, block_num) ||
           (rx_len != 16 * block_num);
}

bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const block_t sblock)
{
    auto rx_len_org = rx_len;
    rx_len          = 0;

    uint16_t sc{service_random_read};
    uint16_t start  = sblock.block();
    uint16_t blocks = rx_len_org >> 4;
    uint16_t last   = std::min<uint16_t>(_activePICC.lastUserBlock(), start + blocks - 1);
    if (!_activePICC.valid() || !rx || !rx_len_org || !_activePICC.isUserBlock(sblock) ||
        !_activePICC.isUserBlock(last)) {
        return false;
    }

    const uint16_t batch_size = get_maxumum_read_blocks(_activePICC.type);
    uint8_t rbuf[16 * batch_size]{};
    block_t block{start};
    auto out = rx;
    uint16_t read_count{};
    while (block.block() <= last) {
        uint16_t num = std::min<uint16_t>(last - block.block() + 1, batch_size);

        uint16_t actual = 16 * num;
        block_t block_list[blocks]{};
        for (uint_fast16_t i = 0; i < num; ++i) {
            block_list[i] = block_t(block.block() + i);
            // M5_LIB_LOGE("  BL[%u]:%02X", i, block_list[i].block());
        }
        // M5_LIB_LOGE("rx_len:%u block_list_num:%u", actual, num);

        if (!_impl->readWithoutEncryption(rbuf, actual, _activePICC, &sc, 1, block_list, num) || actual != 16 * num) {
            return false;
        }
        memcpy(out, rbuf, actual);
        out += actual;
        read_count += actual;
        block.number += num;
    }
    rx_len = read_count;
    return true;
}

bool NFCLayerF::readWithMAC16(uint8_t rx[16], const m5::nfc::f::block_t block)
{
    if (!_authenticated) {
        M5_LIB_LOGW("NOT authenticated");
        return false;
    }
    if (!_activePICC.valid() || (_activePICC.type != Type::FeliCaLite && _activePICC.type != Type::FeliCaLiteS)) {
        return false;
    }

    const bool liteS     = (_activePICC.type == Type::FeliCaLiteS);
    block_t mac_block    = liteS ? lite_s::MAC_A : lite::MAC;
    block_t block_list[] = {block, mac_block};

    uint8_t rbuf[16 * 2]{};
    uint16_t rx_len = sizeof(rbuf);

    if (!read(rbuf, rx_len, block_list, 2) || rx_len < sizeof(rbuf)) {
        M5_LIB_LOGE("Failed to read");
        return false;
    }

    const uint8_t* data_block = rbuf;
    const uint8_t* mac_card   = rbuf + 16;
    const uint8_t* sk1        = _sk;
    const uint8_t* sk2        = _sk + 8;
    const uint8_t* rc         = _rc;
    uint8_t mac_host[8]{};

    if (liteS) {
        uint8_t plain[8] = {
            static_cast<uint8_t>(block.block()),
            0x00,
            static_cast<uint8_t>(mac_block.block()),
            0x00,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        };
        if (!generate_mac(mac_host, plain, sizeof(plain), data_block, 16, sk1, sk2, rc)) {
            return false;
        }
    } else {
        if (!generate_mac(mac_host, nullptr, 0, data_block, 16, sk1, sk2, rc)) {
            return false;
        }
    }

    if (std::memcmp(mac_host, mac_card, 8) != 0) {
        M5_LIB_LOGE("MAC mismatch");
        // M5_LIB_LOGE("Not match %u", liteS);
        m5::utility::log::dump(mac_host, 8, false);
        m5::utility::log::dump(mac_card, 8, false);
        return false;
    }

    std::memcpy(rx, data_block, 16);
    return true;
}

bool NFCLayerF::write16(const m5::nfc::f::block_t block, const uint8_t tx[16], const uint16_t tx_len)
{
    if (_activePICC.valid() && tx && tx_len) {
        uint16_t sc{service_random_read_write};
        uint8_t buf[16]{};
        memcpy(buf, tx, std::min<uint16_t>(16u, tx_len));
        return _impl->writeWithoutEncryption(_activePICC, &sc, 1, &block, 1, buf, 16);
    }
    return false;
}

bool NFCLayerF::write(const m5::nfc::f::block_t sblock, const uint8_t* tx, const uint16_t tx_len)
{
    uint16_t start  = sblock.block();
    uint16_t blocks = (tx_len + 15) >> 4;
    uint16_t last   = std::min<uint16_t>(_activePICC.lastUserBlock(), start + blocks - 1);
    if (!_activePICC.valid() || !tx || !tx_len || !_activePICC.isUserBlock(sblock) || !_activePICC.isUserBlock(last)) {
        return false;
    }

    uint16_t written{};
    for (uint16_t block = start; block <= last; ++block) {
        const uint16_t wsize = std::min<uint16_t>(tx_len - written, 16);
        // M5_LIB_LOGE("write:%02X %u", block, wsize);
        if (!write16(block, tx + written, wsize)) {
            return false;
        }
        written += wsize;
    }
    return true;
}

bool NFCLayerF::writeWithMAC16(const m5::nfc::f::block_t block, const uint8_t tx[16], const uint16_t tx_len)
{
    if (!_authenticated) {
        M5_LIB_LOGW("NOT authenticated");
        return false;
    }
    if (!_activePICC.valid() || (_activePICC.type != Type::FeliCaLite && _activePICC.type != Type::FeliCaLiteS)) {
        return false;
    }

    uint8_t tx2[16]{};
    memcpy(tx2, tx, std::min<uint16_t>(tx_len, sizeof(tx2)));

    const bool liteS   = (_activePICC.type == Type::FeliCaLiteS);
    block_t mac_block  = liteS ? lite_s::MAC_A : lite::MAC;
    const uint8_t* sk1 = _sk;
    const uint8_t* sk2 = _sk + 8;
    const uint8_t* rc  = _rc;
    uint8_t mac_host[8]{};
    uint8_t wcnt[4]{};
    if (liteS) {
        // Read WCNT
        uint8_t wcnt_block[16]{};
        if (!read16(wcnt_block, lite_s::WCNT)) {
            return false;
        }
        std::memcpy(wcnt, wcnt_block, 4);  // Using first 4 bytes (for Link Lite-S mode)

        uint8_t plain[8] = {
            wcnt[0],
            wcnt[1],
            wcnt[2],
            wcnt[3],  //  Always 0 if Lite/Lite-S
            static_cast<uint8_t>(block.block()),
            0x00,
            static_cast<uint8_t>(mac_block.block()),
            0x00,
        };
        if (!generate_mac(mac_host, plain, sizeof(plain), tx2, 16, sk2, sk1, rc)) {
            return false;
        }
    } else {
        if (!generate_mac(mac_host, nullptr /* plain*/, 0 /*plain  num */, tx2, 16, sk1, sk2, rc)) {
            return false;
        }
    }

    uint8_t wbuf[32]{};
    std::memcpy(wbuf, tx2, 16);
    std::memcpy(wbuf + 16, mac_host, 8);
    std::memcpy(wbuf + 24, wcnt, 4);
    block_t block_list[2] = {block, mac_block};

    m5::utility::log::dump(wbuf, 32);
    return false;

    return write_32(block_list, wbuf);
}

bool NFCLayerF::internalAuthenticate(const uint8_t ck[16], const uint16_t ckv, const uint8_t rc[16])
{
    if (!_activePICC.valid() || (_activePICC.type != Type::FeliCaLiteS)) {
        return false;
    }
    return internal_authenticate_lite_s(ck, ckv, rc);
}

bool NFCLayerF::externalAuthenticate(const uint8_t ck[16], const uint16_t ckv)
{
    if (!_activePICC.valid() || _activePICC.type != Type::FeliCaLiteS) {
        return false;
    }
    if (!_authenticated) {
        M5_LIB_LOGW("NOT authenticated");
        return false;
    }
    return external_authenticate_lite_s(ck, ckv);
}

bool NFCLayerF::ndefIsValidFormat(bool& valid)
{
    valid = false;
    return _activePICC.supportsNDEF() && _ndef.isValidFormat(valid, _activePICC.nfcForumTagType());
}

bool NFCLayerF::ndefRead(m5::nfc::ndef::TLV& msg)
{
    msg = TLV{};

    std::vector<TLV> tlvs{};
    if (_activePICC.valid() && _ndef.read(_activePICC.nfcForumTagType(), tlvs, tagBitsMessage)) {
        msg = !tlvs.empty() ? tlvs.front() : TLV{};
        return true;
    }
    return false;
}

bool NFCLayerF::ndefWrite(const m5::nfc::ndef::TLV& msg)
{
    std::vector<TLV> tlvs = {msg};
    return msg.isMessageTLV() && _activePICC.valid() && _ndef.write(_activePICC.nfcForumTagType(), tlvs);
}

bool NFCLayerF::writeSupportNDEF(const bool enabled)
{
    if (!_activePICC.valid() || (_activePICC.type != Type::FeliCaLite && _activePICC.type != Type::FeliCaLiteS)) {
        return false;
    }

    uint8_t buf[16]{};
    if (!read16(buf, lite::MC /* Same as lite_s::MC */)) {
        return false;
    }

    // Already?
    if (buf[3 /* SYS_OP */] == (enabled ? 0x01 : 0x00)) {
        return true;
    }

    buf[3] = enabled ? 0x01 : 0x00;
    if (write16(lite::MC, buf, 16)) {
        _activePICC.format &= ~format_ndef;
        _activePICC.format |= enabled ? format_ndef : 0x00;
        return true;
    }
    return false;
}

bool NFCLayerF::dump()
{
    switch (_activePICC.type) {
        case Type::FeliCaLite:
            return dump_felica_lite();
        case Type::FeliCaLiteS:
            return dump_felica_lite_s();
        case Type::FeliCaStandard:
        case Type::FeliCaPlug:
            M5_LIB_LOGE("Not yet");
            break;
        default:
            M5_LIB_LOGE("Not supported %X", _activePICC.type);
            break;
    }
    return false;
}

bool NFCLayerF::dump(const block_t block)
{
    return _activePICC.valid() && dump_block(block);
}

//
bool NFCLayerF::read_16(uint8_t rx[16], const block_t block, const bool check_valid)
{
    uint16_t rx_len{16};
    uint16_t sc{service_random_read};
    return rx && (check_valid ? _activePICC.valid() : true) &&
           _impl->readWithoutEncryption(rx, rx_len, _activePICC, &sc, 1, &block, 1) && rx_len == 16;
}

bool NFCLayerF::write_32(const m5::nfc::f::block_t block[2], const uint8_t tx[32])
{
    // 2nd block must be MAC_A
    uint16_t sc{service_random_read_write};
    if (block && tx && block[1].block() == lite_s::MAC_A.block()) {
        return _impl->writeWithoutEncryption(_activePICC, &sc, 1, block, 2, tx, 32);
    }
    return false;
}

bool NFCLayerF::internal_authenticate_lite_s(const uint8_t ck[16], const uint16_t ckv, const uint8_t rc[16],
                                             const bool include_wcnt)
{
    _authenticated = false;

    // Make session key
    uint8_t sk[16]{};
    const uint8_t* sk1 = sk;
    const uint8_t* sk2 = sk + 8;
    if (!make_session_key(sk, ck, rc)) {
        M5_LIB_LOGE("Failed to make_session_key");
        return false;
    }
    // m5::utility::log::dump(sk, 16, false);

    // Write RC
    if (!write16(lite::RC, rc, 16)) {
        M5_LIB_LOGE("Failed to write CK");
        return false;
    }

    // Read ID,CKV, WCNT, MAC(Lite)/MAC_A(Lite-S)
    block_t block_list[4] = {lite::ID, lite::CKV,                              //
                             (include_wcnt ? lite_s::WCNT : lite_s::MAC_A),    //
                             (include_wcnt ? lite_s::MAC_A : block_t{0x00})};  //
    uint8_t rbuf[16 * 4]{};
    uint16_t rx_len = include_wcnt ? (4 * 16) : (3 * 16);
    auto needs      = rx_len;
    if (!read(rbuf, rx_len, block_list, include_wcnt ? 4 : 3) || rx_len != needs) {
        M5_LIB_LOGE("Failed to read blocks %u/%u", rx_len, needs);
        return false;
    }
    // m5::utility::log::dump(rbuf, rx_len, false);

    // Compare CKV
    const uint8_t* ckv_block = rbuf + 16;  // 2nd block
    const uint16_t ckv_card  = (static_cast<uint16_t>(ckv_block[0]) << 8) | static_cast<uint16_t>(ckv_block[1]);
    if (ckv_card != ckv) {
        M5_LIB_LOGE("CKV mismatch %04X,%04X", ckv_card, ckv);
        return false;
    }

    // Compare MAC
    uint8_t mac_host[8]{};
    uint8_t plain[8] = {static_cast<uint8_t>(block_list[0].block()),
                        0x00,
                        static_cast<uint8_t>(block_list[1].block()),
                        0x00,
                        static_cast<uint8_t>(block_list[2].block()),
                        0x00,
                        static_cast<uint8_t>(include_wcnt ? block_list[3].block() : 0xFF),
                        static_cast<uint8_t>(include_wcnt ? 0x00 : 0xFF)};
    if (!generate_mac(mac_host, plain, sizeof(plain),                             //
                      rbuf, 32 /*ID + CKV*/ + (include_wcnt != 0) * 16 /*WCNT*/,  //
                      sk1, sk2, rc)) {
        M5_LIB_LOGE("Failed to generate_mac");
        return false;
    }
    // m5::utility::log::dump(mac, 8, false);

    const uint8_t* mac_card = rbuf + 32 + (include_wcnt != 0) * 16;  // MAC_A
    if (std::memcmp(mac_host, mac_card, 8) != 0) {
        M5_LIB_LOGE("MAC mismatch CKV:%04X,%04X", ckv_card, ckv);
        // M5_LIB_LOGE("Not match %u", liteS);
        m5::utility::log::dump(mac_host, 8, false);
        m5::utility::log::dump(mac_card, 8, false);
        return false;
    }

    memcpy(_sk, sk, sizeof(_sk));
    memcpy(_rc, rc, sizeof(_rc));
    _authenticated = true;

    return true;
}

bool NFCLayerF::external_authenticate_lite_s(const uint8_t ck[16], const uint16_t ckv)
{
    // Write RC
    uint8_t rc[16]{};
    make_rc(rc);
    if (!write16(lite_s::RC, rc, sizeof(rc))) {
        return false;
    }

    // internal auth with WCNT
    if (!internal_authenticate_lite_s(ck, ckv, rc)) {
        M5_LIB_LOGE("Failed to internal_authenticate_lite_s");
        return false;
    }

    uint8_t wcnt[16]{};
    if (!read16(wcnt, lite_s::WCNT)) {
        M5_LIB_LOGE("Failed to internal_authenticate_lite_s");
        return false;
    }
    // M5_LIB_LOGE("WCNT:%02X:%02X:%02X:%02X", wcnt[0], wcnt[1], wcnt[2], wcnt[3]);

    //
    uint8_t state[16]{
        0x01 /* Authed */,
    };

    uint8_t plain_w[8] = {wcnt[0],
                          wcnt[1],
                          wcnt[2],
                          wcnt[3],  //  Always 0x00 if Lite/Lite-S
                          static_cast<uint8_t>(lite_s::STATE.block()),
                          0x00,
                          static_cast<uint8_t>(lite_s::MAC_A.block()),
                          0x00};

    const uint8_t* sk1 = _sk;
    const uint8_t* sk2 = _sk + 8;
    uint8_t mac_w[8]{};
    if (!generate_mac(mac_w, plain_w, sizeof(plain_w), state, sizeof(state), sk2, sk1, rc)) {
        M5_LIB_LOGE("Failed to generate_mac");
        return false;
    }

    uint8_t tx[32]{};
    std::memcpy(tx, state, 16);
    std::memcpy(tx + 16, mac_w, 8);
    std::memcpy(tx + 24, wcnt, 4);

    block_t block_list[2] = {lite_s::STATE, lite_s::MAC_A};
    if (!write_32(block_list, tx)) {
        M5_LIB_LOGE("Failed to write_32");
        return false;
    }

    /*
    read16(state, lite_s::STATE);
    M5_LIB_LOGE("=== STATE");
    m5::utility::log::dump(state, 16);
    */

    return true;
}

bool NFCLayerF::dump_felica_lite()
{
    puts(
        "Block: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "------------------------------------------------------");

    bool ret{true};
    for (uint8_t block = 0; block < 0x0F; ++block) {
        ret &= dump_block(block);
    }
    for (uint8_t block = 0x80; block < 0x89; ++block) {
        ret &= dump_block(block);
    }
    return ret;
}

bool NFCLayerF::dump_felica_lite_s()
{
    bool ret{true};
    ret &= dump_felica_lite();
    for (uint8_t block = 0x90; block < 0x93; ++block) {
        // MAC_A(0x91) cannot be read unless written to RC.
        if (block == lite_s::MAC_A) {
            printf("[%04X]:MAC_A needs wrtite to RC\n", block);
            continue;
        }
        ret &= dump_block(block);
    }
    ret &= dump_block(0xA0);
    return ret;
}

bool NFCLayerF::dump_block(m5::nfc::f::block_t block)
{
    uint8_t buf[16]{};

    if (read16(buf, block)) {
        print_block(buf, block.block());
        return true;
    }
    printf("[%04X]:ERROR\n", block.block());
    return false;
}

//
bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr)
{
    if (_activePICC.checkFormat(format_ndef)) {
        return read(rx, rx_len, block_t(saddr));
    }
    rx_len = 0;
    return false;
}
bool NFCLayerF::write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len)
{
    return _activePICC.checkFormat(format_ndef) && write(block_t(saddr), tx, tx_len);
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
