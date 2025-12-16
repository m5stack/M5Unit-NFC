/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_b.hpp
  @brief Common layer for NFC-B

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#include "nfc_layer_b.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include <inttypes.h>
#include <M5Utility.hpp>
#include <algorithm>
#include <esp_random.h>

using namespace m5::nfc;
using namespace m5::nfc::b;
using namespace m5::nfc::ndef;

namespace {

inline bool exists_picc(const std::vector<PICC>& v, const PICC& picc)
{
    return std::find_if(v.begin(), v.end(), [&picc](const PICC& p) {  //
               return memcmp(p.pupi, picc.pupi, 4) == 0;
           }) != v.end();
}

constexpr uint8_t make_request_param(const bool wakeup, const Require slots)
{
    return (wakeup ? 0x08 : 0x00) | (m5::stl::to_underlying(slots) & 0x07);
}

constexpr uint8_t required_slots(const Require slots)
{
    return 1U << m5::stl::to_underlying(slots);
}
}  // namespace

namespace m5 {
namespace nfc {

bool NFCLayerB::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                           const uint32_t timeout_ms, const bool rx_crc)
{
    return _impl->transceive(rx, rx_len, tx, tx_len, timeout_ms, rx_crc);
}

bool NFCLayerB::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return _impl->transmit(tx, tx_len, timeout_ms);
}

bool NFCLayerB::receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms, const bool rx_crc)
{
    return _impl->receive(rx, rx_len, timeout_ms, rx_crc);
}

bool NFCLayerB::detect(m5::nfc::b::PICC& picc, const uint8_t afi, const uint32_t timeout_ms)
{
    std::vector<PICC> piccs{};
    if (detect(piccs, afi, timeout_ms)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

bool NFCLayerB::detect(std::vector<m5::nfc::b::PICC>& piccs, const uint8_t afi, const uint32_t timeout_ms)
{
    piccs.clear();

    auto timeout_at = m5::utility::millis() + timeout_ms;
    do {
        uint8_t rx[ATQB_LENGTH * 16]{};
        uint16_t rx_len = sizeof(rx);
        if (!request(rx, rx_len, afi, Require::Slot1)) {
            continue;
        }

        uint8_t picc_num = rx_len / ATQB_LENGTH;
        for (uint_fast8_t i = 0; i < picc_num; ++i) {
            PICC picc{};
            memcpy(picc.atqb, rx + i * ATQB_LENGTH, ATQB_LENGTH);

            M5_LIB_LOGV("Detected: %s", picc.pupiAsString().c_str());
            if (!exists_picc(piccs, picc)) {
                hlt(picc.pupi);  // If you don't perform hlt, it will be detected again
                picc.type = Type::Unclassified;
                piccs.emplace_back(picc);
            }
        }
        if (piccs.size() >= 16) {
            break;
        }
    } while (m5::utility::millis() <= timeout_at);

    return !piccs.empty();
}

bool NFCLayerB::select(m5::nfc::b::PICC& picc)
{
    // Wakeup for READY
    uint16_t len = ATQB_LENGTH;
    if (!wakeup(picc.atqb, len)) {
        return false;
    }

    // ATTRIB
    uint8_t cmd[1 + 4 + 1 + 1 + 1 + 1] = {m5::stl::to_underlying(Command::ATTRIB)};  // without option
    memcpy(cmd + 1, picc.pupi, 4);
    cmd[5] = 0x00;                           // PARAM1
    cmd[6] = picc.maximumFrameLengthBits();  // PARAM2 | com speed
    cmd[7] = picc.protocol[1] & 0x0F;        // PARAM 3protocol type
    cmd[8] = 0x00;                           // PARAM 4

    std::vector<uint8_t> frame;
    frame.assign(cmd, cmd + sizeof(cmd));

    uint8_t rx[128]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, frame.data(), frame.size(), TIMEOUT_ATTRIB) || !rx_len) {
        M5_LIB_LOGE("Failed to select");
        return false;
    }

    _activePICC = picc;
    return true;
}

bool NFCLayerB::hlt(const uint8_t pupi[4])
{
    if (pupi) {
        uint8_t cmd[1 + 4] = {m5::stl::to_underlying(Command::HLTB)};
        memcpy(cmd + 1, pupi, 4);
        uint8_t rx[1]{};
        uint16_t rx_len = sizeof(rx);
        if (!transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_HLTB) || rx_len < 1) {
            M5_LIB_LOGE("Failed to hlt %02X%02X%02X%02X", cmd[1], cmd[2], cmd[3], cmd[4]);
            return false;
        }
        return rx[0] == 0x00;
    }
    return false;
}

bool NFCLayerB::deselect(const uint8_t pupi[4], const uint8_t cid)
{
    uint8_t cmd[2]   = {m5::stl::to_underlying(cid != 0xFF ? Command::DESELECT_WITH_CID : Command::DESELECT)};
    uint16_t cmd_len = 1 + (cid != 0xFF);
    if (cid != 0xFF) {
        cmd[1] = cid;
    }
    uint8_t rx[2]{};
    uint16_t rx_len = cmd_len;

    if (!transceive(rx, rx_len, cmd, cmd_len, TIMEOUT_DESELECT) || rx_len < cmd_len) {
        M5_LIB_LOGE("Failed to deselecte %02X:%02X", cmd[0], cmd[1]);
        return false;
    }

    if (memcmp(cmd, rx, cmd_len)) {
        m5::utility::log::dump(cmd, cmd_len, false);
        m5::utility::log::dump(rx, cmd_len, false);
        return false;
    }
    return true;
}

bool NFCLayerB::deactivate()
{
    PICC tmp    = _activePICC;
    _activePICC = PICC{};
    return deselect(tmp.pupi) || hlt(tmp.pupi);
}

//
bool NFCLayerB::request_wakeup(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi, const Require slots,
                               const bool wakeup)
{
    if (!atqb || atqb_len < ATQB_LENGTH) {
        return false;
    }

    uint8_t cmd[] = {m5::stl::to_underlying(Command::REQ_WUPB), afi, make_request_param(wakeup, slots)};
    uint8_t rx[1 + ATQB_LENGTH + 2]{};
    uint16_t rx_len = sizeof(rx);
    uint32_t offset{};
    m5::utility::CRC16 crc16(0XFFFF, 0x1021, true, true, 0XFFFF);
    const auto max_slots  = required_slots(slots);
    const auto max_rx_len = atqb_len;
    atqb_len              = 0;

    // Ignore non-responsive slots and proceed to the next one.
    if (transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_REQ_WUP_B, true) && rx_len == sizeof(rx) && rx[0] == 0x50) {
        // Occur collision if CRC error
        const uint16_t crc = crc16.range(rx, ATQB_LENGTH + 1);
        if (crc == ((uint16_t)rx[13] << 8 | rx[12])) {
            memcpy(atqb, rx + 1, ATQB_LENGTH);
            atqb_len += ATQB_LENGTH;
        }
        //        hlt(rx + 1);  // If you don't perform hlt, it will be detected again
    }

    uint8_t slot_marker[1]{};
    for (uint_fast8_t i = 1; (offset + ATQB_LENGTH) < max_rx_len && i < max_slots; ++i) {
        rx_len         = sizeof(rx);
        slot_marker[0] = ((uint8_t)i << 4) | 0x05;
        // Ignore non-responsive slots and proceed to the next one.
        if (!transceive(rx, rx_len, slot_marker, sizeof(slot_marker), TIMEOUT_REQ_WUP_B, true) || rx[0] != 0x50 ||
            rx_len < sizeof(rx)) {
            continue;
        }
        // Occur collision if CRC error
        const uint16_t crc = crc16.range(rx, 1 + ATQB_LENGTH);
        if (crc == ((uint16_t)rx[13] << 8 | rx[12])) {
            memcpy(atqb + atqb_len, rx + 1, ATQB_LENGTH);
            atqb_len += ATQB_LENGTH;
        }
        //        hlt(rx + 1);  // If you don't perform hlt, it will be detected again
    }
    return atqb_len > 0;
}

}  // namespace nfc
}  // namespace m5
