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
#include "nfc/ndef/ndef_message.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>

using namespace m5::nfc::f;
using namespace m5::nfc::ndef;

namespace {

constexpr uint16_t known_system_code_table[] = {
    system_code_wildcard, system_code_ndef, system_code_secure, system_code_shared, system_code_dfc,
};

inline bool exists_system_code(const uint16_t code)
{
    return std::find(std::begin(known_system_code_table), std::end(known_system_code_table), code) !=
           std::end(known_system_code_table);
}

inline bool exists_picc(const std::vector<PICC>& v, const PICC& picc)
{
    return std::find_if(v.begin(), v.end(), [&picc](const PICC& p) { return p == picc; }) != v.end();
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

bool NFCLayerF::detect(m5::nfc::f::PICC& picc, const uint16_t system_code, const uint32_t timeout_ms)
{
    std::vector<PICC> v{};
    uint16_t codes[1] = {system_code};
    if (detect_picc(v, codes, 1, TimeSlot::Slot1, timeout_ms)) {
        if (!exists_system_code(system_code) && picc.format & format_private) {
            picc = v.front();
            return true;
        }
    }
    return false;
}

bool NFCLayerF::detect(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t system_code, m5::nfc::f::TimeSlot time_slot,
                       const uint32_t timeout_ms)
{
    uint16_t codes[1] = {system_code};
    if (!detect_picc(piccs, codes, 1, time_slot, timeout_ms)) {
        return false;
    }

    // Remove items that do not meet the conditions
    if (!piccs.empty() && !exists_system_code(system_code)) {
        auto it =
            std::remove_if(piccs.begin(), piccs.end(), [](PICC& picc) { return (picc.format & format_private) == 0; });
        piccs.erase(it, piccs.end());
    }
    return !piccs.empty();
}

bool NFCLayerF::detect_picc(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t* private_code, const uint8_t pc_size,
                            m5::nfc::f::TimeSlot time_slot, const uint32_t timeout_ms)
{
    uint8_t slots = timeslot_to_slot(time_slot);

    piccs.clear();
    piccs.reserve(slots);

    auto timeout_at = m5::utility::millis() + timeout_ms;
    uint8_t detected{};
    do {
        PICC picc1{}, picc2{};
        uint8_t format{};

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

        // 3. Check private area
        for (uint_fast8_t i = 0; i < pc_size; ++i) {
            auto code = private_code[i];
            if (exists_system_code(code)) {
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

        // 6. Check DEF for FeliCa Lite-S
        if (polling(picc2, system_code_dfc, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            // TODO: read lite-S
            format |= format_shared;
        }

        // 7. Check secure
        if (polling(picc2, system_code_secure, RequestCode::None, time_slot)) {
            if (picc1 != picc2) {
                continue;
            }
            format |= format_secure;
        }

        picc1.format = format;
        piccs.push_back(picc1);
        ++detected;
    } while (detected < slots && m5::utility::millis() <= timeout_at);

    return !piccs.empty();
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
