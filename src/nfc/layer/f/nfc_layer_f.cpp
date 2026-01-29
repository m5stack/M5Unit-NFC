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

using namespace m5::nfc;
using namespace m5::nfc::f;
using namespace m5::nfc::ndef;

namespace {

constexpr uint16_t known_system_code_table[] = {system_code_wildcard, system_code_ndef, system_code_felica_secure_id,
                                                system_code_shared,   system_code_lite, system_code_felica_plug};

inline bool exists_known_system_code(const uint16_t code)
{
    return std::find(std::begin(known_system_code_table), std::end(known_system_code_table), code) !=
           std::end(known_system_code_table);
}

inline bool exists_picc(const std::vector<PICC>& v, const PICC& picc)
{
    return std::find_if(v.begin(), v.end(), [&picc](const PICC& p) {
               return memcmp(p.idm, picc.idm, sizeof(p.idm)) == 0 && memcmp(p.pmm, picc.pmm, sizeof(p.pmm)) == 0;
           }) != v.end();
}

uint32_t get_block_list_size(const block_t* block_list, const uint8_t block_num)
{
    uint32_t sz{};
    if (block_list && block_num) {
        for (uint_fast16_t i = 0; i < block_num; ++i) {
            sz += 2 + block_list[i].is_3byte();
        }
    }
    return sz;
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
    return memcmp(a.m, b.m, 16) == 0;
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
namespace nfc {

uint16_t NFCLayerF::maximum_fifo_depth() const
{
    return _impl->max_fifo_depth();
}

bool NFCLayerF::polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                        const m5::nfc::f::TimeSlot time_slot)
{
    picc = {};

    uint8_t packet[] = {m5::stl::to_underlying(CommandCode::Polling), (uint8_t)(system_code >> 8),
                        (uint8_t)(system_code & 0xFF), m5::stl::to_underlying(request_code),
                        m5::stl::to_underlying(time_slot)};

    uint32_t timeout_ms = TIMEOUT_POLLING * TIMEOUT_POLLING_PICC * timeslot_to_slot(time_slot);

    uint8_t rbuf[18 + ((request_code != RequestCode::None) ? 2 : 0)]{};
    uint16_t rx_len = sizeof(rbuf);
    if (!_impl->transceive(rbuf, rx_len, packet, sizeof(packet), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::Polling)) {
        if (rx_len) {
            M5_LIB_LOGD("Failed to Polling %u %u %u", rx_len, rbuf[0], rbuf[1]);
        }
        return false;
    }

    if (rx_len >= 18 && rbuf[0] >= 18) {
        memcpy(picc.idm, rbuf + 2, sizeof(picc.idm));
        memcpy(picc.pmm, rbuf + 10, sizeof(picc.pmm));
        picc.request_code = request_code;
        if (rbuf[0] >= 20) {
            picc.request_data = ((uint16_t)rbuf[18]) << 8;
            picc.request_data |= (uint16_t)rbuf[19];
        }
        return true;
    }
    return false;
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
    constexpr uint32_t FDT{1};

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
        m5::utility::delay(FDT);

        // Already exists?
        if (exists_picc(piccs, picc1)) {
            continue;
        }

        M5_LIB_LOGV("Detect %s", picc1.idmAsString().c_str());

        _activePICC = picc1;

        // 2. Check IDm for NFCIP-1 Transport Protocol / DFC
        if (picc1.idm[0] == 0x01 && picc1.idm[1] == 0xFE) {
            format |= format_nfcip1;
        } else if (picc1.idm[0] == 0x03 && picc1.idm[1] == 0xFE) {
            format |= format_lite;  // plug or Lite-S
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
            m5::utility::delay(FDT);
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
        m5::utility::delay(FDT);

        // 5. Check shared area
        if (polling(picc2, system_code_shared, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_shared;
        }
        m5::utility::delay(FDT);

        // 6. Check Lite/S
        if (polling(picc2, system_code_lite, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_lite;
        }
        m5::utility::delay(FDT);

        // 7. Check secure
        if (polling(picc2, system_code_felica_secure_id, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            format |= format_secure;
        }
        m5::utility::delay(FDT);

        // Type identification
        if (polling(picc2, system_code_felica_plug, RequestCode::None, time_slot)) {
            if (!is_same_idm_and_pmm(picc1, picc2)) {
                continue;
            }
            type = Type::FeliCaPlug;
        } else {
            // Lite or LiteS?
            if (format & format_lite) {
                uint8_t rbuf[16]{};
                uint16_t rx_len = sizeof(rbuf);
                type = read_without_encryption_impl(rbuf, rx_len, &lite_s::CRC_CHECK, 1, &service_random_read, 1, picc1)
                           ? Type::FeliCaLiteS
                           : Type::FeliCaLite;
                rx_len = sizeof(rbuf);
                if (!read_without_encryption_impl(rbuf, rx_len, &lite::ID, 1, &service_random_read, 1, picc1)) {
                    continue;
                }
                picc1.dfc_format = ((uint16_t)rbuf[8] << 8) | rbuf[9];
            }
        }
        m5::utility::delay(FDT);

        if (type == Type::Unknown) {
            M5_LIB_LOGD("Unknown: %x", format);
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
            if (!request_response_impl(tmp, mode)) {
                M5_LIB_LOGD("Failed to read mode");
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

bool NFCLayerF::requestService(uint16_t key_version[], const uint16_t* node_code, const uint8_t node_num)
{
    if (!_activePICC.valid() || !key_version || !node_code || !node_num || _activePICC.type != Type::FeliCaStandard) {
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8 + 1 + (2 * node_num));

    packet[0] = m5::stl::to_underlying(CommandCode::RequestService);
    memcpy(packet.data() + 1, _activePICC.idm, 8);
    packet[9]  = node_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < node_num; ++i) {
        *p++ = node_code[i] & 0xFF;
        *p++ = node_code[i] >> 8;
    }

    if (packet.size() + 1 > FELICA_MAX_PACKET_LENGTH_REQUEST_SERVICE + 1) {
        return false;
    }
    uint8_t rbuf[FELICA_MAX_PACKET_LENGTH_REQUEST_SERVICE + 1]{};
    uint16_t rx_len = sizeof(rbuf);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    if (!_impl->transceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestService)) {
        M5_LIB_LOGE("Failed to RequestService %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    for (uint_fast8_t i = 0; i < rbuf[10]; ++i) {
        key_version[i] = ((uint16_t)rbuf[12 + i * 2] << 8) | rbuf[11 + i * 2];
    }
    return true;
}

bool NFCLayerF::request_response_impl(const m5::nfc::f::PICC& picc, m5::nfc::f::standard::Mode& mode)
{
    mode = standard::Mode::Mode0;

    if (picc.type != Type::FeliCaStandard) {
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8);

    packet[0] = m5::stl::to_underlying(CommandCode::RequestResponse);
    memcpy(packet.data() + 1, picc.idm, 8);

    if (packet.size() + 2 > FELICA_MAX_PACKET_LENGTH_REQUEST_RESPONSE + 2) {
        return false;
    }
    uint8_t rbuf[FELICA_MAX_PACKET_LENGTH_REQUEST_RESPONSE + 2]{};
    uint16_t rx_len = sizeof(rbuf);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    if (!_impl->transceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < sizeof(rbuf) || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestResponse)) {
        M5_LIB_LOGE("Failed to RequestResponse %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    mode = static_cast<standard::Mode>(rbuf[10]);
    return true;
}

bool NFCLayerF::requestSystemCode(uint16_t code_list[255], uint8_t& code_num)
{
    if (code_list) {
        memset(code_list, 0x00, 2 * 255);
    }

    if (!code_list || !_activePICC.valid() || _activePICC.type != Type::FeliCaStandard) {
        return false;
    }

    std::vector<uint8_t> packet{};
    uint32_t timeout_ms = 10;  // TODO

    packet.resize(1 + 8);

    packet[0] = m5::stl::to_underlying(CommandCode::RequestSystemCode);
    memcpy(packet.data() + 1, _activePICC.idm, 8);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 2 * 255]{};
    uint16_t rx_len = sizeof(rbuf);

    if (!_impl->transceive(rbuf, rx_len, packet.data(), packet.size(), timeout_ms)  //
        || rx_len < 11 || rbuf[1] != m5::stl::to_underlying(ResponseCode::RequestSystemCode)) {
        M5_LIB_LOGE("Failed to RequestResponse %u", rx_len);
        return false;
    }

    // m5::utility::log::dump(rbuf, rx_len, false);

    code_num      = rbuf[10];
    const auto* p = rbuf + 11;
    for (uint_fast16_t i = 0; i < code_num; ++i) {
        code_list[i] = p[1] | ((uint16_t)p[0] << 8);
        p += 2;
    }
    return true;
}

bool NFCLayerF::read16(uint8_t rx[16], const m5::nfc::f::block_t* block, const uint8_t block_num,
                       const uint16_t service_code)
{
    uint16_t rx_len{16};
    return _activePICC.valid() &&
           read_without_encryption_impl(rx, rx_len, block, block_num, &service_code, 1, _activePICC) && rx_len == 16;
}

bool NFCLayerF::read_without_encryption_impl(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t* block_list,
                                             const uint8_t block_num, const uint16_t* service_code,
                                             const uint8_t service_num, const PICC& picc)
{
    auto rx_org_len = rx_len;
    rx_len          = 0;

    if (!rx || !rx_org_len || !block_list || !block_num || !service_code || !service_num || service_num > 16 ||
        block_num > FELICA_MAX_BLOCKS) {
        return false;
    }

    std::vector<uint8_t> packet{};
    const uint32_t block_size = get_block_list_size(block_list, block_num);
    uint32_t timeout_ms       = 50;  // TODO

    packet.resize(1 + 8 + 1 + (2 * service_num) + 1 + block_size);

    packet[0] = m5::stl::to_underlying(CommandCode::ReadWithoutEncryption);
    memcpy(packet.data() + 1, picc.idm, 8);
    packet[9]  = service_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < service_num; ++i) {
        *p++ = service_code[i] & 0xFF;
        *p++ = service_code[i] >> 8;
    }
    *p++ = block_num;
    for (uint_fast8_t i = 0; i < block_num; ++i) {
        block_t ble = block_list[i];
        p += ble.store(p);
    }

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 1 + 1 + 16 * FELICA_MAX_BLOCKS]{};
    uint16_t actual = sizeof(rbuf);
    if (!_impl->transceive(rbuf, actual, packet.data(), packet.size(), timeout_ms) || actual < 12 || (rbuf[0] < 11) ||
        rbuf[1] != m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption) ||  //
        (rbuf[10] /*status 1*/ != 0x00) || (rbuf[11] /*status 2*/ != 0x00)) {
        M5_LIB_LOGD("Failed to read (%02X, %u) a:%u r[0]:%u %02X%02X", block_list[0].block(), rx_org_len, actual,
                    rbuf[0], rbuf[10], rbuf[11]);
        return false;
    }
    //    const uint8_t blocks = rbuf[11];
    rx_len = std::min<uint16_t>(actual - 13, rx_org_len);
    memcpy(rx, rbuf + 13, rx_len);
    return true;
}

bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const block_t sblock)
{
    auto rx_org_len = rx_len;
    rx_len          = 0;

    if (!rx || !rx_org_len) {
        return false;
    }

    uint16_t sc{service_random_read};
    uint16_t start  = sblock.block();
    uint16_t blocks = rx_org_len >> 4;
    if (blocks == 0) {
        return false;
    }
    if (blocks > FELICA_MAX_BLOCKS) {
        return false;
    }
    uint16_t last = std::min<uint16_t>(_activePICC.lastUserBlock(), start + blocks - 1);
    if (!_activePICC.valid() || !rx || !rx_org_len || !_activePICC.isUserBlock(sblock) ||
        !_activePICC.isUserBlock(last)) {
        return false;
    }

    const uint16_t batch_size = get_maxumum_read_blocks(_activePICC.type);
    std::vector<uint8_t> rbuf(16 * batch_size);
    block_t block{start};
    auto out = rx;
    uint16_t read_count{};
    while (block.block() <= last) {
        uint16_t num = std::min<uint16_t>(last - block.block() + 1, batch_size);

        uint16_t actual = 16 * num;
        block_t block_list[FELICA_MAX_BLOCKS]{};
        for (uint_fast16_t i = 0; i < num; ++i) {
            block_list[i] = block_t(block.block() + i);
            // M5_LIB_LOGE("  BL[%u]:%02X", i, block_list[i].block());
        }
        // M5_LIB_LOGE("rx_len:%u block_list_num:%u", actual, num);

        if (!read(rbuf.data(), actual, block_list, num, &sc, 1) || actual != 16 * num) {
            return false;
        }
        memcpy(out, rbuf.data(), actual);
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

    if (!read_without_encryption_impl(rbuf, rx_len, block_list, 2, &service_random_read, 1, _activePICC) ||
        rx_len < sizeof(rbuf)) {
        M5_LIB_LOGD("Failed to read %u", rx_len);
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
        uint8_t buf[16]{};
        memcpy(buf, tx, std::min<uint16_t>(16u, tx_len));
        return write_without_encryption_impl(_activePICC, &block, 1, &service_random_read_write, 1, buf, 16);
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

bool NFCLayerF::write_without_encryption_impl(const m5::nfc::f::PICC& picc, const m5::nfc::f::block_t* block_list,
                                              const uint8_t block_num, const uint16_t* service_code,
                                              const uint8_t service_num, const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || !block_list || !block_num || !service_code || !service_num || service_num > 16) {
        return false;
    }

    std::vector<uint8_t> packet{};
    const uint32_t block_size = get_block_list_size(block_list, block_num);
    uint32_t timeout_ms       = 10;  // TODO

    packet.resize(1 + 8 + 1 + (2 * service_num) + 1 + block_size + tx_len);

    packet[0] = m5::stl::to_underlying(CommandCode::WriteWithoutEncryption);
    memcpy(packet.data() + 1, picc.idm, sizeof(picc.idm));
    packet[9]  = service_num;
    uint8_t* p = packet.data() + 10;
    for (uint_fast8_t i = 0; i < service_num; ++i) {
        *p++ = service_code[i] & 0xFF;
        *p++ = service_code[i] >> 8;
    }
    *p++ = block_num;
    for (uint_fast8_t i = 0; i < block_num; ++i) {
        block_t ble = block_list[i];
        p += ble.store(p);
    }
    memcpy(p, tx, tx_len);

    // m5::utility::log::dump(packet.data(), packet.size(), false);

    uint8_t rbuf[1 + 1 + 8 + 1 + 1]{};
    uint16_t actual = sizeof(rbuf);
    if (!_impl->transceive(rbuf, actual, packet.data(), packet.size(), timeout_ms) || actual < 12 || (rbuf[0] < 11) ||
        rbuf[1] != m5::stl::to_underlying(ResponseCode::WriteWithoutEncryption) ||  //
        (rbuf[10] /*status 1*/ != 0x00) || (rbuf[11] /*status 2*/ != 0x00)) {
        // m5::utility::log::dump(rbuf, actual, false);
        M5_LIB_LOGD("Failed to write(%02X, %u) %u %u %02X %02X", block_list[0].block(), tx_len, actual, rbuf[0],
                    rbuf[10], rbuf[11]);
        return false;
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
    block_t block_list[2] = {block, mac_block};  // 2nd block must be MAC_A
    return write_without_encryption_impl(_activePICC, block_list, 2, &service_random_read_write, 1, wbuf, sizeof(wbuf));
}

bool NFCLayerF::clearSPAD()
{
    const uint8_t w[16 * 14]{};
    return write(0, w, sizeof(w));
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
    return msg.isMessageTLV() && _activePICC.valid() && _ndef.write(_activePICC.nfcForumTagType(), tlvs, false);
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
            // case Type::FeliCaStandard:
            // case Type::FeliCaPlug:
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
    if (!read(rbuf, rx_len, block_list, include_wcnt ? 4 : 3, &service_random_read, 1) || rx_len != needs) {
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

    block_t block_list[2] = {lite_s::STATE, lite_s::MAC_A};  // 2nd block must be MAC_A
    if (!write_without_encryption_impl(_activePICC, block_list, 2, &service_random_read_write, 1, tx, sizeof(tx))) {
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
bool NFCLayerF::read(uint8_t* rx, uint16_t& rx_len, const uint16_t saddr)
{
    if (_activePICC.checkFormat(format_ndef)) {
        return read(rx, rx_len, block_t(static_cast<uint8_t>(saddr & 0xFF)));
    }
    M5_LIB_LOGW("PICC Not sopport NDEF");
    rx_len = 0;
    return false;
}
bool NFCLayerF::write(const uint16_t saddr, const uint8_t* tx, const uint16_t tx_len)
{
    return _activePICC.checkFormat(format_ndef) && write(block_t(static_cast<uint8_t>(saddr & 0xFF)), tx, tx_len);
}

}  // namespace nfc
}  // namespace m5
