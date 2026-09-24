/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_b.cpp
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

// ISO/IEC 14443-4 FSDI table (Frame Size for Device Index, bit[7:4] of ATTRIB PARAM2)
constexpr uint8_t fsdi_for_size(const uint16_t bytes)
{
    return (bytes >= 256)   ? 8
           : (bytes >= 128) ? 7
           : (bytes >= 96)  ? 6
           : (bytes >= 64)  ? 5
           : (bytes >= 48)  ? 4
           : (bytes >= 40)  ? 3
           : (bytes >= 32)  ? 2
           : (bytes >= 24)  ? 1
                            : 0;
}
}  // namespace

namespace m5 {
namespace nfc {

NFCLayerB::~NFCLayerB() = default;

uint16_t NFCLayerB::maximum_fifo_depth() const
{
    return _impl->max_fifo_depth();
}

bool NFCLayerB::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                           const uint32_t timeout_ms)
{
    return _impl->transceive(rx, rx_len, tx, tx_len, timeout_ms);
}

bool NFCLayerB::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return _impl->transmit(tx, tx_len, timeout_ms);
}

bool NFCLayerB::receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    return _impl->receive(rx, rx_len, timeout_ms);
}

bool NFCLayerB::detect(m5::nfc::b::PICC& picc, const uint8_t afi, const uint32_t timeout_ms,
                       const uint32_t req_timeout_ms)
{
    std::vector<PICC> piccs{};
    if (detect(piccs, afi, 1, timeout_ms, req_timeout_ms)) {
        picc = piccs.front();
        return true;
    }
    return false;
}

bool NFCLayerB::detect(std::vector<m5::nfc::b::PICC>& piccs, const uint8_t afi, const uint8_t max_piccs,
                       const uint32_t timeout_ms, const uint32_t req_timeout_ms)
{
    piccs.clear();

    const auto start_at = m5::utility::millis();
    do {
        uint8_t rx[ATQB_LENGTH]{};
        uint16_t rx_len = sizeof(rx);
        if (!request(rx, rx_len, afi, Require::Slot1, req_timeout_ms)) {
            continue;
        }

        hlt(rx);  // If you don't perform hlt, it will be detected again

        PICC picc{};
        memcpy(picc.atqb, rx, ATQB_LENGTH);

        M5_LIB_LOGE("Detected: %s", picc.pupiAsString().c_str());
        if (!exists_picc(piccs, picc)) {
            picc.type = Type::Unclassified;
            piccs.emplace_back(picc);
        }
        if (piccs.size() >= max_piccs) {
            break;
        }
    } while (!m5::utility::hasElapsed(start_at, timeout_ms));

    return !piccs.empty();
}

bool NFCLayerB::select(m5::nfc::b::PICC& picc, const uint32_t timeout_ms)
{
    // Wakeup for READY
    uint16_t len = ATQB_LENGTH;
    if (!wakeup(picc.atqb, len)) {
        return false;
    }

    M5_LIB_LOGI("ATQB protocol: %02X %02X %02X (FSCI=%u, ISO14443-4=%d, FWI=%u)", picc.protocol[0], picc.protocol[1],
                picc.protocol[2], (picc.protocol[1] >> 4) & 0x0F, (picc.protocol[1] & 0x01),
                (picc.protocol[2] >> 4) & 0x0F);

    // ATTRIB PARAM2 (per ISO/IEC 14443-3 §7.10.2 with b1 = LSB):
    //   bit[3:0] = FSDI (PCD's max receive frame size index)
    //   bit[5:4] = PCD->PICC bit rate divisor
    //   bit[7:6] = PICC->PCD bit rate divisor
    // Take min(PCD FIFO, PICC FSCI) so the PICC chains I-blocks within what we can receive.
    const uint16_t pcd_rx_cap = maximum_fifo_depth() - 2 /*CRC*/;
    const uint8_t pcd_fsdi    = fsdi_for_size(pcd_rx_cap);
    const uint8_t picc_fsci   = picc.maximumFrameLengthBits();
    const uint8_t fsdi        = std::min<uint8_t>(pcd_fsdi, picc_fsci);

    // ATTRIB
    uint8_t cmd[1 + 4 + 1 + 1 + 1 + 1] = {m5::stl::to_underlying(Command::ATTRIB)};  // without option
    memcpy(cmd + 1, picc.pupi, 4);
    cmd[5] = 0x00;                     // PARAM1
    cmd[6] = (uint8_t)(fsdi & 0x0F);   // PARAM2: FSDI(PCD cap) bit[3:0] | rates=0 (106k both)
    cmd[7] = picc.protocol[1] & 0x0F;  // PARAM3 protocol type
    cmd[8] = 0x00;                     // PARAM 4

    std::vector<uint8_t> frame;
    frame.assign(cmd, cmd + sizeof(cmd));

    uint8_t rx[128]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, frame.data(), frame.size(), timeout_ms) || !rx_len) {
        M5_LIB_LOGE("Failed to select: rx_len=%u", rx_len);
        return false;
    }

    _activePICC = picc;
    return true;
}

bool NFCLayerB::hlt(const uint8_t pupi[4], const uint32_t timeout_ms)
{
    if (pupi) {
        uint8_t cmd[1 + 4] = {m5::stl::to_underlying(Command::HLTB)};
        memcpy(cmd + 1, pupi, 4);
        uint8_t rx[1 + 2]{};  // 1 byte payload + 2 byte CRC_B
        uint16_t rx_len = sizeof(rx);
        if (!transceive(rx, rx_len, cmd, sizeof(cmd), timeout_ms) || rx_len < 1) {
            M5_LIB_LOGE("Failed to hlt %02X%02X%02X%02X", cmd[1], cmd[2], cmd[3], cmd[4]);
            return false;
        }
        return rx[0] == 0x00;
    }
    return false;
}

bool NFCLayerB::deselect(const uint8_t pupi[4], const uint8_t cid, const uint32_t timeout_ms)
{
    uint8_t cmd[2]   = {m5::stl::to_underlying(cid != 0xFF ? Command::DESELECT_WITH_CID : Command::DESELECT)};
    uint16_t cmd_len = 1 + (cid != 0xFF);
    if (cid != 0xFF) {
        cmd[1] = cid;
    }
    uint8_t rx[2 + 2]{};  // payload (1 or 2) + 2 byte CRC_B
    uint16_t rx_len = sizeof(rx);

    if (!transceive(rx, rx_len, cmd, cmd_len, timeout_ms) || rx_len < cmd_len) {
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
                               const bool wakeup, const uint32_t timeout_ms)
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
    if (transceive(rx, rx_len, cmd, sizeof(cmd), timeout_ms) && rx_len == sizeof(rx) && rx[0] == 0x50) {
        // Occur collision if CRC error
        const uint16_t crc = crc16.range(rx, ATQB_LENGTH + 1);
        if (crc == ((uint16_t)rx[13] << 8 | rx[12])) {
            memcpy(atqb, rx + 1, ATQB_LENGTH);
            atqb_len += ATQB_LENGTH;
        }
        //             hlt(rx + 1);  // If you don't perform hlt, it will be detected again
    }

    uint8_t slot_marker[1]{};
    for (uint_fast8_t i = 1; (offset + ATQB_LENGTH) < max_rx_len && i < max_slots; ++i) {
        rx_len         = sizeof(rx);
        slot_marker[0] = ((uint8_t)i << 4) | 0x05;
        // Ignore non-responsive slots and proceed to the next one.
        if (!transceive(rx, rx_len, slot_marker, sizeof(slot_marker), timeout_ms) || rx[0] != 0x50 ||
            rx_len < sizeof(rx)) {
            continue;
        }
        // Occur collision if CRC error
        const uint16_t crc = crc16.range(rx, 1 + ATQB_LENGTH);
        if (crc == ((uint16_t)rx[13] << 8 | rx[12])) {
            memcpy(atqb + atqb_len, rx + 1, ATQB_LENGTH);
            atqb_len += ATQB_LENGTH;
        }
        //                hlt(rx + 1);  // If you don't perform hlt, it will be detected again
    }
    return atqb_len > 0;
}

}  // namespace nfc
}  // namespace m5
