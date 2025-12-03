/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_f.cpp
  @brief Common layer for NFC-F related units
*/
#include "nfc_layer_f.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>

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
            if (format) {
                type = Type::FeliCaStandard;
            } else {
                continue;
            }
        }

        // Re-check
        if (type == Type::FeliCaStandard) {
            Mode mode{};
            if (!_impl->requestResponse(mode, _activePICC)) {
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
        _activePICC = picc;
        return true;
    }
    return false;
}

bool NFCLayerF::deactivate()
{
    _activePICC = PICC{};
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

bool NFCLayerF::requestResponse(m5::nfc::f::Mode& mode)
{
    return _activePICC.valid() && _impl->requestResponse(mode, _activePICC);
}

bool NFCLayerF::requestSystemCode(uint16_t code_list[255], uint8_t& code_num)
{
    return _activePICC.valid() && _impl->requestSystemCode(code_list, code_num, _activePICC);
}

bool NFCLayerF::read_16(uint8_t rx[16], const block_t block, const bool check_valid)
{
    uint16_t rx_len{16};
    uint16_t sc{service_random_read};
    return rx && (check_valid ? _activePICC.valid() : true) &&
           _impl->readWithoutEncryption(rx, rx_len, _activePICC, &sc, 1, &block, 1) && rx_len == 16;
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

bool NFCLayerF::ndefIsValidFormat(bool& valid)
{
    valid = false;
    return _activePICC.supportsNDEF() && _ndef.isValidFormat(_activePICC.nfcForumTagType(), valid);
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
uint16_t NFCLayerF::firstUserBlock() const
{
    return _activePICC.firstUserBlock();
}
uint16_t NFCLayerF::lastUserBlock() const
{
    return _activePICC.lastUserBlock();
}

uint8_t NFCLayerF::maximumReadBlocks() const
{
    return _activePICC.maximumReadBlocks();
}

uint8_t NFCLayerF::maximumWriteBlocks() const
{
    return _activePICC.maximumWriteBlocks();
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
