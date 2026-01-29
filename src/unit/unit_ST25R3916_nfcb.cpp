/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfcb.cpp
  @brief class UnitST25R3916 implementation for NFC-B
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc;
using namespace m5::nfc::b;

// clang-format off
#pragma GCC optimize("O3")
// clang-format on

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::B)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace m5 {
namespace unit {
// -------------------------------- For NFC-B
bool UnitST25R3916::configure_nfc_b()
{
    // 1. Mode and Bitrate configuration
    if (!writeInitiatorOperationMode(InitiatorOperationMode::ISO14443B, tr_am) ||
        !writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K) ||  //
        !writeSettingsISO14443B(0x00)) {
        return false;
    }

    // 2. NFCIP-1 and Stream mode (required for NFC-B)
    if (!writeNFCIP1PassiveTargetDefinition(0x5D) ||  // fdel, d_ac_ap2p, d_212_424_1r, d_106_ac_a
        !writeStreamModeDefinition(0x38)) {
        return false;
    }

    // 3. Auxiliary definition
    if (!writeAuxiliaryDefinition(0x00)) {
        return false;
    }

    // 4. Receiver configuration for NFC-B (106kbps)
    if (!writeReceiverConfiguration1(0x04) ||                               // No z600k filter
        !writeReceiverConfiguration2(sqm_dyn | agc_en | agc_m | agc6_3) ||  // 0x3D
        !writeReceiverConfiguration3(0x00) || !writeReceiverConfiguration4(0x00)) {
        return false;
    }

    // 5. Timer configuration
    if (!writeMaskReceiveTimer(0x07) || !writeNoResponseTimer1(0x10) || !writeNoResponseTimer2(0x0D) ||
        !writeTimerAndEMVControl(0x23) || !writeGeneralPurposeTimer1(0x00) || !writeGeneralPurposeTimer2(0x58) ||
        !writePPON2FieldWaiting(0x80)) {
        return false;
    }

    // 6. Interrupt masks
    if (!writeMaskMainInterrupt(0x85) || !writeMaskTimerAndNFCInterrupt(0xA6) ||
        !writeMaskErrorAndWakeupInterrupt(0x0F) || !writeMaskPassiveTargetInterrupt(0x7B)) {
        return false;
    }

    // 7. TX Driver and antenna
    if (!writeTXDriver(0x70) || !writePassiveTargetModulation(0x5F) ||
        !writeExternalFieldDetectorActivationThreshold(0x13) ||
        !writeExternalFieldDetectorDeactivationThreshold(0x02)) {
        return false;
    }

    // 8. Space-B registers for NFC-B
    if (!write_register8(REG_EMD_SUPPRESSION_CONFIGURATION, 0xC4) ||
        !write_register8(REG_SUBCARRIER_START_TIMER, 0x14) || !write_register8(REG_P2P_RECEIVER_CONFIGURATION, 0x0C) ||
        !writeCorrelatorConfiguration1(0x1B) || !writeCorrelatorConfiguration2(0x00) ||
        !write_register8(REG_SQUELCH_TIMER, 0x00) || !write_register8(REG_NFC_FIELD_ON_GUARD_TIMER, 0x00) ||
        !write_register8(REG_AUXILIARY_MODULATION_SETTING, 0x10) || !write_register8(REG_TX_DRIVER_TIMING, 0x7C) ||
        !write_register8(REG_RESISTIVE_AM_MODULATION, 0x80) || !writeRegulatorVoltageControl(0xD0)) {
        return false;
    }

    // 9. Field on
    return nfc_initial_field_on();
}

#if 0
// Old implementation using val_table (working reference)
namespace {
constexpr uint8_t val_table[] = {
    0x07, 0x3C, 0xCB, 0x14, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x38, 0x00, 0x04, 0x3D, 0x00, 0x00, 0x07,
    0x10, 0x0D, 0x23, 0x00, 0x58, 0x80, 0x85, 0xA6, 0x0F, 0x7B, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x00, 0xE1, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0xAB, 0x38, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
}  // namespace

bool UnitST25R3916::configure_nfc_b()
{
    uint8_t reg = 0x00;
    for (auto&& v : val_table) {
        write_register8(reg, v);
        ++reg;
    }

    {
        uint16_t r{};
        r = 0x05;
        write_register8(r, 0xC4);
        r = 0x06;
        write_register8(r, 0x14);
        r = 0x0B;
        write_register8(r, 0x0C);
        r = 0x0C;
        write_register8(r, 0x1B);
        r = 0x0D;
        write_register8(r, 0x00);
        r = 0x0F;
        write_register8(r, 0x00);
        r = 0x15;
        write_register8(r, 0x00);
        r = 0x28;
        write_register8(r, 0x10);
        r = 0x29;
        write_register8(r, 0x7C);
        r = 0x2A;
        write_register8(r, 0x80);
        r = 0x2B;
        write_register8(r, 0x04);
        r = 0x2C;
        write_register8(r, 0xD0);
    }

    nfc_initial_field_on();

    return true;
}
#endif

bool UnitST25R3916::nfcbTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                   const uint32_t timeout_ms)
{
    return nfcbTransmit(tx, tx_len, timeout_ms) && nfcbReceive(rx, rx_len, timeout_ms);
}

bool UnitST25R3916::nfcbTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    if (!tx || !tx_len) {
        return false;
    }
    if (timeout_ms && !write_fwt_timer(timeout_ms)) {
        return false;
    }

    if (!clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) ||  //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(tx, tx_len) ||
        !writeNumberOfTransmittedBytes(tx_len, 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
    return true;
}

// Always with CRC_B
bool UnitST25R3916::nfcbReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org) {
        return false;
    }

#if 0    
    uint8_t rbuf[256]{};
    if (!wait_for_FIFO(timeout_ms, sizeof(rbuf))) {
        M5_LIB_LOGD("Timeout");
        return false;
    }
    uint16_t actual{};
    auto bb = readFIFO(actual, rbuf, sizeof(rbuf));
    if (!bb) {
        M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rx_len_org);
        return false;
    }
    rx_len = std::min<uint16_t>(actual, rx_len_org);
    memcpy(rx, rbuf, rx_len);
#else
    if (!wait_for_FIFO(timeout_ms, rx_len_org)) {
        M5_LIB_LOGD("Timeout");
        return false;
    }

    uint16_t actual{};
    auto bb = readFIFO(actual, rx, rx_len_org);
    if (bb) {
        M5_LIB_LOGV("readFIFO %u/%u %u/%u %02X", actual, rx_len_org, bb >> 16, bb & 0xFFFF, rx[0]);
        rx_len = actual;
        return bb;
    }
    M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rx_len_org);
    return false;
#endif
    return true;
}

}  // namespace unit
}  // namespace m5

/*
14:07:01.211 > [  5260][I][RFAL.cpp:44] dump_regs(): Reg[0x00]:0x07:00000111
14:07:01.217 > [  5267][I][RFAL.cpp:44] dump_regs(): Reg[0x01]:0x3C:00111100
14:07:01.223 > [  5273][I][RFAL.cpp:44] dump_regs(): Reg[0x02]:0xCB:11001011
14:07:01.230 > [  5279][I][RFAL.cpp:44] dump_regs(): Reg[0x03]:0x14:00010100
14:07:01.236 > [  5286][I][RFAL.cpp:44] dump_regs(): Reg[0x04]:0x00:00000000
14:07:01.243 > [  5292][I][RFAL.cpp:44] dump_regs(): Reg[0x05]:0x00:00000000
14:07:01.249 > [  5299][I][RFAL.cpp:44] dump_regs(): Reg[0x06]:0x00:00000000
14:07:01.256 > [  5305][I][RFAL.cpp:44] dump_regs(): Reg[0x07]:0x00:00000000
14:07:01.262 > [  5312][I][RFAL.cpp:44] dump_regs(): Reg[0x08]:0x5D:01011101
14:07:01.268 > [  5318][I][RFAL.cpp:44] dump_regs(): Reg[0x09]:0x38:00111000
14:07:01.275 > [  5324][I][RFAL.cpp:44] dump_regs(): Reg[0x0A]:0x00:00000000
14:07:01.281 > [  5331][I][RFAL.cpp:44] dump_regs(): Reg[0x0B]:0x04:00000100
14:07:01.288 > [  5337][I][RFAL.cpp:44] dump_regs(): Reg[0x0C]:0x3D:00111101
14:07:01.294 > [  5344][I][RFAL.cpp:44] dump_regs(): Reg[0x0D]:0x00:00000000
14:07:01.301 > [  5350][I][RFAL.cpp:44] dump_regs(): Reg[0x0E]:0x00:00000000
14:07:01.307 > [  5357][I][RFAL.cpp:44] dump_regs(): Reg[0x0F]:0x07:00000111
14:07:01.313 > [  5363][I][RFAL.cpp:44] dump_regs(): Reg[0x10]:0x10:00010000
14:07:01.320 > [  5369][I][RFAL.cpp:44] dump_regs(): Reg[0x11]:0x0D:00001101
14:07:01.326 > [  5376][I][RFAL.cpp:44] dump_regs(): Reg[0x12]:0x23:00100011
14:07:01.333 > [  5382][I][RFAL.cpp:44] dump_regs(): Reg[0x13]:0x00:00000000
14:07:01.339 > [  5389][I][RFAL.cpp:44] dump_regs(): Reg[0x14]:0x58:01011000
14:07:01.345 > [  5395][I][RFAL.cpp:44] dump_regs(): Reg[0x15]:0x80:10000000
14:07:01.352 > [  5401][I][RFAL.cpp:44] dump_regs(): Reg[0x16]:0x85:10000101
14:07:01.358 > [  5408][I][RFAL.cpp:44] dump_regs(): Reg[0x17]:0xA6:10100110
14:07:01.365 > [  5414][I][RFAL.cpp:44] dump_regs(): Reg[0x18]:0x0F:00001111
14:07:01.371 > [  5421][I][RFAL.cpp:44] dump_regs(): Reg[0x19]:0x7B:01111011
14:07:01.378 > [  5427][I][RFAL.cpp:44] dump_regs(): Reg[0x1A]:0x00:00000000
14:07:01.384 > [  5434][I][RFAL.cpp:44] dump_regs(): Reg[0x1B]:0x00:00000000
14:07:01.390 > [  5440][I][RFAL.cpp:44] dump_regs(): Reg[0x1C]:0x00:00000000
14:07:01.397 > [  5446][I][RFAL.cpp:44] dump_regs(): Reg[0x1D]:0x00:00000000
14:07:01.403 > [  5453][I][RFAL.cpp:44] dump_regs(): Reg[0x1E]:0x02:00000010
14:07:01.410 > [  5459][I][RFAL.cpp:44] dump_regs(): Reg[0x1F]:0x00:00000000
14:07:01.416 > [  5466][I][RFAL.cpp:44] dump_regs(): Reg[0x20]:0x00:00000000
14:07:01.423 > [  5472][I][RFAL.cpp:44] dump_regs(): Reg[0x21]:0x00:00000000
14:07:01.429 > [  5479][I][RFAL.cpp:44] dump_regs(): Reg[0x22]:0x00:00000000
14:07:01.435 > [  5485][I][RFAL.cpp:44] dump_regs(): Reg[0x23]:0x48:01001000
14:07:01.442 > [  5491][I][RFAL.cpp:44] dump_regs(): Reg[0x24]:0x00:00000000
14:07:01.448 > [  5498][I][RFAL.cpp:44] dump_regs(): Reg[0x25]:0xE1:11100001
14:07:01.455 > [  5504][I][RFAL.cpp:44] dump_regs(): Reg[0x26]:0x82:10000010
14:07:01.461 > [  5511][I][RFAL.cpp:44] dump_regs(): Reg[0x27]:0x82:10000010
14:07:01.468 > [  5517][I][RFAL.cpp:44] dump_regs(): Reg[0x28]:0x70:01110000
14:07:01.474 > [  5524][I][RFAL.cpp:44] dump_regs(): Reg[0x29]:0x5F:01011111
14:07:01.480 > [  5530][I][RFAL.cpp:44] dump_regs(): Reg[0x2A]:0x13:00010011
14:07:01.487 > [  5536][I][RFAL.cpp:44] dump_regs(): Reg[0x2B]:0x02:00000010
14:07:01.493 > [  5543][I][RFAL.cpp:44] dump_regs(): Reg[0x2C]:0x00:00000000
14:07:01.500 > [  5549][I][RFAL.cpp:44] dump_regs(): Reg[0x2D]:0xAB:10101011
14:07:01.506 > [  5556][I][RFAL.cpp:44] dump_regs(): Reg[0x2E]:0x38:00111000
14:07:01.512 > [  5562][I][RFAL.cpp:44] dump_regs(): Reg[0x2F]:0x00:00000000
14:07:01.519 > [  5568][I][RFAL.cpp:44] dump_regs(): Reg[0x30]:0x00:00000000
14:07:01.525 > [  5575][I][RFAL.cpp:44] dump_regs(): Reg[0x31]:0x10:00010000
14:07:01.532 > [  5581][I][RFAL.cpp:44] dump_regs(): Reg[0x32]:0x00:00000000
14:07:01.538 > [  5588][I][RFAL.cpp:44] dump_regs(): Reg[0x33]:0x00:00000000
14:07:01.545 > [  5594][I][RFAL.cpp:44] dump_regs(): Reg[0x34]:0x00:00000000
14:07:01.551 > [  5601][I][RFAL.cpp:44] dump_regs(): Reg[0x35]:0x00:00000000
14:07:01.557 > [  5607][I][RFAL.cpp:44] dump_regs(): Reg[0x36]:0x00:00000000
14:07:01.564 > [  5613][I][RFAL.cpp:44] dump_regs(): Reg[0x37]:0x00:00000000
14:07:01.570 > [  5620][I][RFAL.cpp:44] dump_regs(): Reg[0x38]:0x00:00000000
14:07:01.577 > [  5626][I][RFAL.cpp:44] dump_regs(): Reg[0x39]:0x00:00000000
14:07:01.583 > [  5633][I][RFAL.cpp:44] dump_regs(): Reg[0x3A]:0x00:00000000
14:07:01.590 > [  5639][I][RFAL.cpp:44] dump_regs(): Reg[0x3B]:0x00:00000000
14:07:01.596 > [  5646][I][RFAL.cpp:44] dump_regs(): Reg[0x3C]:0x00:00000000
14:07:01.602 > [  5652][I][RFAL.cpp:44] dump_regs(): Reg[0x3D]:0x00:00000000
14:07:01.609 > [  5658][I][RFAL.cpp:44] dump_regs(): Reg[0x3E]:0x00:00000000
14:07:01.615 > [  5665][I][RFAL.cpp:44] dump_regs(): Reg[0x3F]:0x2A:00101010
14:07:01.620 > [  5671][W][RFAL.cpp:46] dump_regs(): SpaceB
14:07:01.627 > [  5676][I][RFAL.cpp:48] dump_regs(): Reg[0x00]:0xC4:11000100
14:07:01.633 > [  5683][I][RFAL.cpp:48] dump_regs(): Reg[0x01]:0x14:00010100
14:07:01.640 > [  5689][I][RFAL.cpp:48] dump_regs(): Reg[0x02]:0x0C:00001100
14:07:01.646 > [  5695][I][RFAL.cpp:48] dump_regs(): Reg[0x03]:0x1B:00011011
14:07:01.652 > [  5702][I][RFAL.cpp:48] dump_regs(): Reg[0x04]:0x00:00000000
14:07:01.659 > [  5708][I][RFAL.cpp:48] dump_regs(): Reg[0x05]:0x00:00000000
14:07:01.665 > [  5715][I][RFAL.cpp:48] dump_regs(): Reg[0x06]:0x00:00000000
14:07:01.672 > [  5721][I][RFAL.cpp:48] dump_regs(): Reg[0x07]:0x10:00010000
14:07:01.678 > [  5728][I][RFAL.cpp:48] dump_regs(): Reg[0x08]:0x7C:01111100
14:07:01.684 > [  5734][I][RFAL.cpp:48] dump_regs(): Reg[0x09]:0x80:10000000
14:07:01.691 > [  5740][I][RFAL.cpp:48] dump_regs(): Reg[0x0A]:0x04:00000100
14:07:01.697 > [  5747][I][RFAL.cpp:48] dump_regs(): Reg[0x0B]:0xD0:11010000
14:07:01.704 > [  5753][I][RFAL.cpp:48] dump_regs(): Reg[0x0C]:0x00:00000000
14:07:01.710 > [  5760][I][RFAL.cpp:48] dump_regs(): Reg[0x0D]:0x00:00000000
14:07:01.717 > [  5766][I][RFAL.cpp:48] dump_regs(): Reg[0x0E]:0x00:00000000
14:07:01.723 > [  5773][I][RFAL.cpp:48] dump_regs(): Reg[0x0F]:0x00:00000000
*/
