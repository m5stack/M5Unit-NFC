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
    return std::find_if(v.begin(), v.end(), [&picc](const PICC& p) { return p == picc; }) != v.end();
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
                    if (picc1 != picc2) {
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
            if (picc1 != picc2) {
                continue;
            }
            format |= format_ndef;
        }

        // 5. Check shared area
        if (polling(picc2, system_code_shared, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            format |= format_shared;
        }

        // 6. Check DFC
        if (polling(picc2, system_code_dfc, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            format |= format_dfc;
        }

        // 7. Check secure
        if (polling(picc2, system_code_felica_secure_id, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            format |= format_secure;
        }

        // Type identification
        if (polling(picc2, system_code_felica_plug, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            type = Type::FeliCaPlug;
        } else {
            // Lite or LiteS?
            if (format & format_dfc) {
                uint8_t rbuf[16]{};
                type = read16(rbuf, picc1, 0xA0 /* CRC_CHECK */) ? Type::FeliCaLiteS : Type::FeliCaLite;
                if (!read16(rbuf, picc1, 0x82)) {  // Read ID(DFC format)
                    continue;
                }
                picc1.dfc_format = rbuf[8] | ((uint16_t)rbuf[9] << 8);
            }
        }

        //
        if (type == Type::Unknown && format) {
            type = Type::FeliCaStandard;
        }

        //
        picc1.format = format;
        picc1.type   = type;

        piccs.push_back(picc1);
        ++detected;
    } while (detected < slots && m5::utility::millis() <= timeout_at);

    return detected > 0;
}

bool NFCLayerF::requestService(uint16_t& key_version, const m5::nfc::f::PICC& picc, const uint16_t node_code)
{
    uint16_t n[1] = {node_code};
    uint16_t k[1]{};
    key_version = KEY_VERIOSN_NONE;
    if (requestService(k, picc, n, 1)) {
        key_version = k[0];
        return true;
    }
    return false;
}

bool NFCLayerF::requestService(uint16_t key_version[], const m5::nfc::f::PICC& picc, const uint16_t* node_code,
                               const uint8_t node_size)
{
    return _impl->requestService(key_version, picc, node_code, node_size);
}

bool NFCLayerF::read16(uint8_t rx[16], const m5::nfc::f::PICC& picc, const block_t block)
{
    uint16_t rx_len{16};
    uint16_t sc{service_random_read};
    return rx && _impl->readWithoutEncryption(rx, rx_len, picc, &sc, 1, &block, 1);
}

bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::PICC& picc, const block_t sblock)
{
    auto rx_len_org = rx_len;
    rx_len          = 0;

    uint16_t sc{service_random_read};
    uint16_t start  = sblock.block();
    uint16_t blocks = rx_len_org >> 4;
    uint16_t last   = std::min<uint16_t>(picc.lastUserBlock(), start + blocks - 1);
    if (!rx || !rx_len_org || !picc.isUserBlock(sblock) || !picc.isUserBlock(last)) {
        return false;
    }

    const uint16_t batch_size = get_maxumum_read_blocks(picc.type);
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

        if (!_impl->readWithoutEncryption(rbuf, actual, picc, &sc, 1, block_list, num) || actual != 16 * num) {
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

bool NFCLayerF::write16(const m5::nfc::f::PICC& picc, const m5::nfc::f::block_t block, const uint8_t tx[16],
                        const uint16_t tx_len)
{
    if (tx && tx_len) {
        uint16_t sc{service_random_read_write};
        uint8_t buf[16]{};
        memcpy(buf, tx, std::min<uint16_t>(16u, tx_len));
        return _impl->writeWithoutEncryption(picc, &sc, 1, &block, 1, buf, 16);
    }
    return false;
}

bool NFCLayerF::write(const m5::nfc::f::PICC& picc, const m5::nfc::f::block_t sblock, const uint8_t* tx,
                      const uint16_t tx_len)
{
    if (!tx || !tx_len) {
        return false;
    }

    uint16_t start  = sblock.block();
    uint16_t blocks = (tx_len + 15) >> 4;
    uint16_t last   = std::min<uint16_t>(picc.lastUserBlock(), start + blocks - 1);
    if (!tx || !tx_len || !picc.isUserBlock(sblock) || !picc.isUserBlock(last)) {
        return false;
    }

    uint16_t written{};
    for (uint16_t block = start; block <= last; ++block) {
        const uint16_t wsize = std::min<uint16_t>(tx_len - written, 16);
        // M5_LIB_LOGE("write:%02X %u", block, wsize);
        if (!write16(picc, block, tx + written, wsize)) {
            return false;
        }
        written += wsize;
    }
    return true;
}

bool NFCLayerF::dump(const PICC& picc)
{
    switch (picc.type) {
        case Type::FeliCaLite:
            return dump_felica_lite(picc);
        case Type::FeliCaLiteS:
            return dump_felica_lite_s(picc);
        case Type::FeliCaStandard:
            M5_LIB_LOGE("Not yet");
            break;
        default:
            M5_LIB_LOGE("Not yet");
            break;
    }
    return false;
}

bool NFCLayerF::dump(const PICC& picc, const block_t block)
{
    // TODO
    return dump_block(picc, block);
}

//

bool NFCLayerF::dump_felica_lite(const m5::nfc::f::PICC& picc)
{
    puts(
        "Block: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "------------------------------------------------------");

    bool ret{true};
    for (uint8_t block = 0; block < 0x0F; ++block) {
        ret &= dump_block(picc, block);
    }
    for (uint8_t block = 0x80; block < 0x89; ++block) {
        ret &= dump_block(picc, block);
    }
    return ret;
}

bool NFCLayerF::dump_felica_lite_s(const m5::nfc::f::PICC& picc)
{
    bool ret{true};
    ret &= dump_felica_lite(picc);
    for (uint8_t block = 0x90; block < 0x93; ++block) {
        // MAC_A(0x91) cannot be read unless written to RC.
        if (block == 0x91) {
            printf("[%04X]:MAC_A needs wrtite to RC\n", block);
            continue;
        }
        ret &= dump_block(picc, block);
    }
    ret &= dump_block(picc, 0xA0);
    return ret;
}

bool NFCLayerF::dump_block(const m5::nfc::f::PICC& picc, m5::nfc::f::block_t block)
{
    uint8_t buf[16]{};

    if (read16(buf, picc, block)) {
        print_block(buf, block.block());
        return true;
    }
    printf("[%04X]:ERROR\n", block.block());
    return false;
}

//
bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr)
{
    return false;
}
bool NFCLayerF::write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len)
{
    return false;
}
uint16_t NFCLayerF::firstUserBlock() const
{
    return 0;
}
uint16_t NFCLayerF::lastUserBlock() const
{
    return 0;
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
