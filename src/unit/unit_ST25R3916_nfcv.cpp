/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfcv.cpp
  @brief class UnitST25R3916 implementation for NFC-V
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;

using namespace m5::nfc;
using namespace m5::nfc::v;

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::V)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace {

constexpr uint8_t val_table[] = {
    0x07, 0x3C, 0xCB, 0x70, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x38, 0x01, 0x13, 0x2D, 0x00, 0x00, 0x41,
    0x00, 0x52, 0x20, 0x01, 0x84, 0x80, 0x85, 0xA7, 0x0F, 0x7B, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xB0, 0x00, 0xE0, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0xCB, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void parse_inventory(PICC& picc, const uint8_t rx[10])
{
    picc.dsfID = rx[1];
    for (uint_fast8_t i = 0; i < 8; ++i) {
        picc.uid[i] = rx[9 - i];
    }
}

void make_frame(uint8_t frame[10 /* at least */], const uint8_t req, const int8_t cmd, const PICC* picc = nullptr)
{
    if (frame) {
        frame[0] = req;
        frame[1] = cmd;
        if (picc) {
            for (int i = 0; i < 8; ++i) {
                frame[2 + i] = picc->uid[7 - i];
            }
        }
    }
}

}  // namespace

namespace m5 {
namespace unit {
// -------------------------------- For NFC-V
bool UnitST25R3916::configure_nfc_v()
{
    constexpr uint8_t lp0{0x10};
    constexpr uint8_t h80{0x02};
    constexpr uint8_t z12k{0x01};
    // Low-pass 600Khz, First stage zero 12Khz, third stage zero 80Khz
    writeReceiverConfiguration1(lp0 | h80 | z12k);

    constexpr uint8_t sqm_dyn{0x20};
    constexpr uint8_t agc_en{0x08};
    constexpr uint8_t agc_m{0x04};
    constexpr uint8_t agc6_3{0x01};
    writeReceiverConfiguration2(sqm_dyn | agc_en | agc_m | agc6_3);
    writeReceiverConfiguration3(0x00);  // ?
    writeReceiverConfiguration4(0x00);  // ?

    constexpr uint8_t corr_s4{0x10};  // RX bit rate 106kb/s = 33, RX bit rates 212 to 848 kb/s = 17
    constexpr uint8_t corr_s1{0x02};  // Collision detection level
    constexpr uint8_t corr_s0{0x01};  // 11 : 53%
    //
    writeCorrelatorConfiguration1(corr_s4 | corr_s1 | corr_s0);

    constexpr uint8_t corr_s8{0x01};  // 1: 424 kHz subcarrier stream mode
    writeCorrelatorConfiguration2(corr_s8);
    modify_bit_register8(REG_MODE_DEFINITION, 0x00, tr_am);

    modify_bit_register8(REG_TX_DRIVER, 0xF0, 0xF0);  // am_mode 0, keep d_res (modulation 40%)

    modify_bit_register8(REG_ISO14443A_SETTINGS, 0x1C, 0x1D);  // [1110] 33 16 7 3

#if 1
    uint8_t reg = 0x00;
    for (auto&& v : val_table) {
        //        if (reg < 2) {
        //            continue;
        //        }
        write_register8(reg, v);
        ++reg;
    }

    {
        uint16_t r{};
        r = 0x05;
        writeRegister8(r, 0x40);
        r = 0x06;
        writeRegister8(r, 0x14);
        r = 0x0B;
        writeRegister8(r, 0x0C);
        r = 0x0C;
        writeRegister8(r, 0x13);
        r = 0x0D;
        writeRegister8(r, 0x01);
        r = 0x0F;
        writeRegister8(r, 0x00);
        r = 0x15;
        writeRegister8(r, 0x00);
        r = 0x28;
        writeRegister8(r, 0x10);
        r = 0x29;
        writeRegister8(r, 0x7C);
        r = 0x2A;
        writeRegister8(r, 0x80);
        r = 0x2B;
        writeRegister8(r, 0x04);
        r = 0x2C;
        writeRegister8(r, 0xD0);
    }
#endif

    nfc_initial_field_on();

    return true;
}

bool UnitST25R3916::nfcvTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                   const uint32_t timeout_ms, const ModulationMode mode)
{
    CHECK_MODE();
    if (!nfcv_transmit(tx, tx_len, mode, timeout_ms)) {
        return false;
    }
    return nfcv_receive(rx, rx_len, timeout_ms);
}

bool UnitST25R3916::nfcv_transmit(const uint8_t* tx, const uint16_t tx_len, const ModulationMode mode,
                                  const uint32_t timeout_ms)
{
    if (!tx || !tx_len) {
        return false;
    }

    //m5::utility::log::dump(tx, tx_len, false);

    // Encode
    std::vector<uint8_t> frame{};
    if (!encode_VCD(frame, mode, tx, tx_len)) {
        M5_LIB_LOGE("Failed to encode");
        return false;
    }
    //m5::utility::log::dump(frame.data(), frame.size(), false);

    // Send
    if (timeout_ms && !write_fwt_timer(timeout_ms)) {
        return false;
    }
    if (!clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(frame.data(), frame.size()) ||
        !writeNumberOfTransmittedBytes(frame.size(), 0) || !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        return false;
    }
    return true;
}

bool UnitST25R3916::nfcv_receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org) {
        return false;
    }

    uint8_t rbuf[256]{};
    if (!wait_for_FIFO(timeout_ms, sizeof(rbuf))) {
        return false;
    }
    uint16_t actual{};
    auto bb = readFIFO(actual, rbuf, sizeof(rbuf));
    if (!bb) {
        M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rx_len_org);
        return false;
    }

    // Decode
    std::vector<uint8_t> frame{};
    if (!decode_VICC(frame, rbuf, actual)) {
        M5_LIB_LOGE("Failed to decode");
        // m5::utility::log::dump(rx, rx_len, false);
        return false;
    }

    // m5::utility::log::dump(frame.data(), frame.size(), false);
    rx_len = std::min<uint32_t>(frame.size(), rx_len_org);
    memcpy(rx, frame.data(), rx_len);
    return true;
}

bool UnitST25R3916::nfcvInventry(std::vector<m5::nfc::v::PICC>& piccs, const bool single)
{
    piccs.clear();

    const uint8_t req = address_flag | inventory_flag | (single ? nb_slots_flag : 0x00);
    uint8_t cmd[3]    = {req, m5::stl::to_underlying(Command::Inventory), 0x00 /* No mask */};

    uint8_t rx[160]{};
    uint16_t rx_len = sizeof(rx);
    if (!nfcvTransceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_INVENTORY) || !rx_len || rx[0] != 0x00) {
        //M5_LIB_LOGE("Failed to Inventory %u", rx_len);
        return false;
    }

    // Suppoort 16 slot Not yet...
    PICC picc{};
    parse_inventory(picc, rx);
    piccs.emplace_back(picc);
    return true;
}

bool UnitST25R3916::nfcvStayQuiet(const m5::nfc::v::PICC& picc)
{
    if (!picc.valid()) {
        return false;
    }
    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::StayQuiet), &picc);

    if (!nfcv_transmit(frame, sizeof(frame), ModulationMode::OneOf4, TIMEOUT_STAY_QUIET)) {
        M5_LIB_LOGE("Failed to StayQuiet");
        return false;
    }

    // No response upon success
    auto irq = wait_for_interrupt(I_txe32 | I_rxe32, TIMEOUT_STAY_QUIET);
    if (is_irq32_rxe(irq)) {
        // Error response
        M5_LIB_LOGE("Failed to StayQuiet");
        return false;
    }
    return is_irq32_txe(irq);
}

bool UnitST25R3916::nfcvSelect(const m5::nfc::v::PICC& picc)
{
    if (!picc.valid()) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::Select), &picc);

    uint8_t rx[8]{};
    uint16_t rx_len = sizeof(rx);
    if (!nfcvTransceive(rx, rx_len, frame, sizeof(frame), TIMEOUT_SELECT) || !rx_len) {
        m5::utility::log::dump(rx, rx_len, false);
        M5_LIB_LOGE("Failed to Select %u", rx_len);
        return false;
    }
    return rx[0] == 0x00;
}

bool UnitST25R3916::nfcvResetToReady(const m5::nfc::v::PICC& picc)
{
    return nfcv_reset_to_ready(&picc);
}

bool UnitST25R3916::nfcvResetToReady()
{
    return nfcv_reset_to_ready(nullptr);
}

bool UnitST25R3916::nfcv_reset_to_ready(const PICC* picc)
{
    if ((picc ? !picc->valid() : false)) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, ((picc ? address_flag : select_flag) | data_rate_flag),
               m5::stl::to_underlying(Command::ResetToReady), picc);

    uint8_t rx[8]{};
    uint16_t rx_len = sizeof(rx);
    if (!nfcvTransceive(rx, rx_len, frame, (picc ? 10 : 2), TIMEOUT_RESET_TO_READY) || !rx_len) {
        m5::utility::log::dump(rx, rx_len, false);
        M5_LIB_LOGE("Failed to ResetToRequest %02X %p %u", frame[0], picc, rx_len);
        return false;
    }
    return rx[0] == 0x00;
}

bool UnitST25R3916::nfcvGetSystemInformation(m5::nfc::v::PICC& picc)
{
    if (picc.uid[0] != 0xE0) {
        return false;
    }

    uint8_t frame[10]{};
    make_frame(frame, address_flag | data_rate_flag, m5::stl::to_underlying(Command::GetSystemInformaion), &picc);

    uint8_t rx[15]{};
    uint16_t rx_len = sizeof(rx);
    if (!nfcvTransceive(rx, rx_len, frame, sizeof(frame), TIMEOUT_GET_SYSTEM_INFORMATION) || !rx_len || rx[0] != 0x00) {
        M5_LIB_LOGE("Failed to transcieve %u %02X", rx_len, rx[1] /* error code */);
        return false;
    }

    const uint8_t info_flags = rx[1];
    uint32_t idx{2 + 8};

    // info_flags bit0: DSFID present
    if (info_flags & 0x01) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("DSFID flag set but no data");
            return true;
        }
        picc.dsfID = rx[idx++];
    }

    // info_flags bit1: AFI present
    if (info_flags & 0x02) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("AFI flag set but no data");
            return true;
        }
        picc.afi = rx[idx++];
    }

    // info_flags bit2: VICC memory size present
    if (info_flags & 0x04) {
        if (idx + 1 >= rx_len) {
            M5_LIB_LOGW("MemSize flag set but not enough data");
            return true;
        }
        const uint16_t nb = rx[idx++];  // number of blocks - 1
        const uint8_t bs  = rx[idx++];  // (block size - 1) in bits4..0
        picc.blocks       = nb + 1;
        picc.block_size   = (bs & 0x1FU) + 1U;
    }

    // info_flags bit3: IC reference present
    if (info_flags & 0x08) {
        if (idx >= rx_len) {
            M5_LIB_LOGW("ICRef flag set but no data");
            return true;
        }
        picc.icRef = rx[idx++];
    }

    return true;
}

bool UnitST25R3916::nfcvReadSingleBlock(uint8_t rx[32], const m5::nfc::v::PICC& picc, const uint8_t block)
{
    return nfcv_read_single_block(rx, address_flag | data_rate_flag, &picc, block);
}

bool UnitST25R3916::nfcvReadSingleBlock(uint8_t rx[32], const uint8_t block)
{
    return nfcv_read_single_block(rx, select_flag | data_rate_flag, nullptr, block);
}

bool UnitST25R3916::nfcv_read_single_block(uint8_t rx[32], const uint8_t req, const m5::nfc::v::PICC* picc,
                                           const uint8_t block)
{
    if (!rx || (picc ? !picc->valid() : false)) {
        return false;
    }

    uint8_t frame[10 + 1]{};
    make_frame(frame, req, m5::stl::to_underlying(Command::ReadSingleBlock), picc);
    frame[picc ? 10 : 2] = block;

    uint8_t rbuf[32 + 1]{};
    uint16_t rx_len = sizeof(rbuf);
    if (!nfcvTransceive(rbuf, rx_len, frame, picc ? 11 : 3, TIMEOUT_READ_SINGLE_BLOCK) || !rx_len || rbuf[0] != 0x00) {
        M5_LIB_LOGD("Failed to transcieve %02X %u %02X", req, rx_len, rbuf[1] /* error code */);
        return false;
    }
    memcpy(rx, rbuf + 1, rx_len - 1);
    return true;
}

bool UnitST25R3916::nfcvWriteSingleBlock(const m5::nfc::v::PICC& picc, const uint8_t block, const uint8_t* tx,
                                         const uint8_t tx_len, const bool opt)
{
    return nfcv_write_single_block(&picc, block, address_flag | data_rate_flag | (opt ? option_flag : 0), tx, tx_len);
}

bool UnitST25R3916::nfcvWriteSingleBlock(const uint8_t block, const uint8_t* tx, const uint8_t tx_len, const bool opt)
{
    return nfcv_write_single_block(nullptr, block, select_flag | data_rate_flag | (opt ? option_flag : 0), tx, tx_len);
}

bool UnitST25R3916::nfcv_write_single_block(const m5::nfc::v::PICC* picc, const uint8_t block, const uint8_t req,
                                            const uint8_t* tx, const uint8_t tx_len)
{
    CHECK_MODE();

    if (!tx || !tx_len || tx_len > 32 || (picc ? !picc->valid() : false)) {
        return false;
    }

    uint8_t frame[2 + 8 + 1 + tx_len]{};
    make_frame(frame, req, m5::stl::to_underlying(Command::WriteSingleBlock), picc);

    uint32_t offset = picc ? 10 : 2;
    frame[offset++] = block;
    memcpy(frame + offset, tx, tx_len);
    offset += tx_len;

    uint8_t rx[32]{};
    uint16_t rx_len = sizeof(rx);
    if (!nfcvTransceive(rx, rx_len, frame, offset, TIMEOUT_WRITE_SINGLE_BLOCK) || !rx_len || rx[0] != 0x00) {
        M5_LIB_LOGD("Failed to transcieve %02X %u %02X", req, rx_len, rx[1] /* error code */);
        return false;
    }
    return true;
}

}  // namespace unit
}  // namespace m5

#if 0
  , MODE_ENTRY_7_REG((RFAL_ANALOG_CONFIG_POLL | RFAL_ANALOG_CONFIG_TECH_NFCV | RFAL_ANALOG_CONFIG_BITRATE_COMMON |
  RFAL_ANALOG_CONFIG_RX) , ST25R3916_REG_AUX,  ST25R3916_REG_AUX_dis_corr, ST25R3916_REG_AUX_dis_corr_coherent /* Use
  Pulse Receiver */
                    ,
                    ST25R3916_REG_RX_CONF1, 0xFF, 0x13, ST25R3916_REG_RX_CONF2, 0xFF, 0x2D, ST25R3916_REG_RX_CONF3,
                    0xFF, 0x00, ST25R3916_REG_RX_CONF4, 0xFF, 0x00, ST25R3916_REG_CORR_CONF1, 0xFF, 0x13,
                    ST25R3916_REG_CORR_CONF2, 0xFF, 0x01)

    , ST25R3916_REG_MODE, ST25R3916_REG_MODE_tr_am, ST25R3916_REG_MODE_tr_am_ook /* Use OOK modulation */
        ,
        ST25R3916_REG_TX_DRIVER, ST25R3916_REG_TX_DRIVER_am_mod_mask, 0xF0 /* Set modulation index for AWS */
        ,
        ST25R3916_REG_ISO14443A_NFC, ST25R3916_REG_ISO14443A_NFC_p_len_mask,
        0x1c /* Set modulation pulse length p_len */
        ,
        ST25R3916_REG_AWS_CONF2, ST25R3916_REG_AWS_CONF2_am_sym, 0x00 /* Nonsymerical shape (for OOK) */
        ,
        ST25R3916_REG_AWS_CONF2, ST25R3916_REG_AWS_CONF2_en_modsink,
        ST25R3916_REG_AWS_CONF2_en_modsink /* AWS enable strong sink (en_modsink) */
        ,
        ST25R3916_REG_AWS_CONF2, ST25R3916_REG_AWS_CONF2_am_filt_mask, 0x06 /* Medium fast AWS filter constant */
#endif

/*
RFAL
11:39:38.163 > [  4095][W][RFAL.cpp:42] dump_regs(): SpaceA
11:39:38.170 > [  4098][I][RFAL.cpp:44] dump_regs(): Reg[0x00]:0x07:00000111
11:39:38.176 > [  4105][I][RFAL.cpp:44] dump_regs(): Reg[0x01]:0x3C:00111100
11:39:38.183 > [  4111][I][RFAL.cpp:44] dump_regs(): Reg[0x02]:0xCB:11001011
11:39:38.189 > [  4118][I][RFAL.cpp:44] dump_regs(): Reg[0x03]:0x70:01110000
11:39:38.196 > [  4124][I][RFAL.cpp:44] dump_regs(): Reg[0x04]:0x00:00000000
11:39:38.202 > [  4130][I][RFAL.cpp:44] dump_regs(): Reg[0x05]:0x00:00000000
11:39:38.208 > [  4137][I][RFAL.cpp:44] dump_regs(): Reg[0x06]:0x00:00000000
11:39:38.215 > [  4143][I][RFAL.cpp:44] dump_regs(): Reg[0x07]:0x00:00000000
11:39:38.221 > [  4150][I][RFAL.cpp:44] dump_regs(): Reg[0x08]:0x5D:01011101
11:39:38.228 > [  4156][I][RFAL.cpp:44] dump_regs(): Reg[0x09]:0x38:00111000
11:39:38.234 > [  4162][I][RFAL.cpp:44] dump_regs(): Reg[0x0A]:0x01:00000001
11:39:38.241 > [  4169][I][RFAL.cpp:44] dump_regs(): Reg[0x0B]:0x13:00010011
11:39:38.247 > [  4175][I][RFAL.cpp:44] dump_regs(): Reg[0x0C]:0x2D:00101101
11:39:38.253 > [  4182][I][RFAL.cpp:44] dump_regs(): Reg[0x0D]:0x00:00000000
11:39:38.260 > [  4188][I][RFAL.cpp:44] dump_regs(): Reg[0x0E]:0x00:00000000
11:39:38.266 > [  4195][I][RFAL.cpp:44] dump_regs(): Reg[0x0F]:0x41:01000001
11:39:38.273 > [  4201][I][RFAL.cpp:44] dump_regs(): Reg[0x10]:0x00:00000000
11:39:38.279 > [  4207][I][RFAL.cpp:44] dump_regs(): Reg[0x11]:0x52:01010010
11:39:38.285 > [  4214][I][RFAL.cpp:44] dump_regs(): Reg[0x12]:0x20:00100000
11:39:38.292 > [  4220][I][RFAL.cpp:44] dump_regs(): Reg[0x13]:0x01:00000001
11:39:38.298 > [  4227][I][RFAL.cpp:44] dump_regs(): Reg[0x14]:0x84:10000100
11:39:38.305 > [  4233][I][RFAL.cpp:44] dump_regs(): Reg[0x15]:0x80:10000000
11:39:38.311 > [  4240][I][RFAL.cpp:44] dump_regs(): Reg[0x16]:0x85:10000101
11:39:38.318 > [  4246][I][RFAL.cpp:44] dump_regs(): Reg[0x17]:0xA7:10100111
11:39:38.324 > [  4252][I][RFAL.cpp:44] dump_regs(): Reg[0x18]:0x0F:00001111
11:39:38.330 > [  4259][I][RFAL.cpp:44] dump_regs(): Reg[0x19]:0x7B:01111011
11:39:38.337 > [  4265][I][RFAL.cpp:44] dump_regs(): Reg[0x1A]:0x00:00000000
11:39:38.343 > [  4272][I][RFAL.cpp:44] dump_regs(): Reg[0x1B]:0x20:00100000
11:39:38.350 > [  4278][I][RFAL.cpp:44] dump_regs(): Reg[0x1C]:0x00:00000000
11:39:38.356 > [  4285][I][RFAL.cpp:44] dump_regs(): Reg[0x1D]:0x00:00000000
11:39:38.362 > [  4291][I][RFAL.cpp:44] dump_regs(): Reg[0x1E]:0x00:00000000
11:39:38.369 > [  4297][I][RFAL.cpp:44] dump_regs(): Reg[0x1F]:0x00:00000000
11:39:38.375 > [  4304][I][RFAL.cpp:44] dump_regs(): Reg[0x20]:0x00:00000000
11:39:38.382 > [  4310][I][RFAL.cpp:44] dump_regs(): Reg[0x21]:0x00:00000000
11:39:38.388 > [  4317][I][RFAL.cpp:44] dump_regs(): Reg[0x22]:0x00:00000000
11:39:38.395 > [  4323][I][RFAL.cpp:44] dump_regs(): Reg[0x23]:0xB0:10110000
11:39:38.401 > [  4329][I][RFAL.cpp:44] dump_regs(): Reg[0x24]:0x00:00000000
11:39:38.407 > [  4336][I][RFAL.cpp:44] dump_regs(): Reg[0x25]:0xE0:11100000
11:39:38.414 > [  4342][I][RFAL.cpp:44] dump_regs(): Reg[0x26]:0x82:10000010
11:39:38.420 > [  4349][I][RFAL.cpp:44] dump_regs(): Reg[0x27]:0x82:10000010
11:39:38.427 > [  4355][I][RFAL.cpp:44] dump_regs(): Reg[0x28]:0x70:01110000
11:39:38.433 > [  4362][I][RFAL.cpp:44] dump_regs(): Reg[0x29]:0x5F:01011111
11:39:38.440 > [  4368][I][RFAL.cpp:44] dump_regs(): Reg[0x2A]:0x13:00010011
11:39:38.446 > [  4374][I][RFAL.cpp:44] dump_regs(): Reg[0x2B]:0x02:00000010
11:39:38.452 > [  4381][I][RFAL.cpp:44] dump_regs(): Reg[0x2C]:0x00:00000000
11:39:38.459 > [  4387][I][RFAL.cpp:44] dump_regs(): Reg[0x2D]:0xCB:11001011
11:39:38.465 > [  4394][I][RFAL.cpp:44] dump_regs(): Reg[0x2E]:0x00:00000000
11:39:38.472 > [  4400][I][RFAL.cpp:44] dump_regs(): Reg[0x2F]:0x00:00000000
11:39:38.478 > [  4407][I][RFAL.cpp:44] dump_regs(): Reg[0x30]:0x00:00000000
11:39:38.485 > [  4413][I][RFAL.cpp:44] dump_regs(): Reg[0x31]:0x10:00010000
11:39:38.491 > [  4419][I][RFAL.cpp:44] dump_regs(): Reg[0x32]:0x00:00000000
11:39:38.497 > [  4426][I][RFAL.cpp:44] dump_regs(): Reg[0x33]:0x00:00000000
11:39:38.504 > [  4432][I][RFAL.cpp:44] dump_regs(): Reg[0x34]:0x00:00000000
11:39:38.510 > [  4439][I][RFAL.cpp:44] dump_regs(): Reg[0x35]:0x00:00000000
11:39:38.517 > [  4445][I][RFAL.cpp:44] dump_regs(): Reg[0x36]:0x00:00000000
11:39:38.523 > [  4451][I][RFAL.cpp:44] dump_regs(): Reg[0x37]:0x00:00000000
11:39:38.530 > [  4458][I][RFAL.cpp:44] dump_regs(): Reg[0x38]:0x00:00000000
11:39:38.536 > [  4464][I][RFAL.cpp:44] dump_regs(): Reg[0x39]:0x00:00000000
11:39:38.542 > [  4471][I][RFAL.cpp:44] dump_regs(): Reg[0x3A]:0x00:00000000
11:39:38.549 > [  4477][I][RFAL.cpp:44] dump_regs(): Reg[0x3B]:0x00:00000000
11:39:38.555 > [  4484][I][RFAL.cpp:44] dump_regs(): Reg[0x3C]:0x00:00000000
11:39:38.562 > [  4490][I][RFAL.cpp:44] dump_regs(): Reg[0x3D]:0x00:00000000
11:39:38.568 > [  4496][I][RFAL.cpp:44] dump_regs(): Reg[0x3E]:0x00:00000000
11:39:38.574 > [  4503][I][RFAL.cpp:44] dump_regs(): Reg[0x3F]:0x2A:00101010
11:39:38.579 > [  4509][W][RFAL.cpp:46] dump_regs(): SpaceB
11:39:38.586 > [  4514][I][RFAL.cpp:48] dump_regs(): Reg[0x05]:0x40:01000000
11:39:38.592 > [  4521][I][RFAL.cpp:48] dump_regs(): Reg[0x06]:0x14:00010100
11:39:38.599 > [  4527][I][RFAL.cpp:48] dump_regs(): Reg[0x0B]:0x0C:00001100
11:39:38.605 > [  4534][I][RFAL.cpp:48] dump_regs(): Reg[0x0C]:0x13:00010011
11:39:38.612 > [  4540][I][RFAL.cpp:48] dump_regs(): Reg[0x0D]:0x01:00000001
11:39:38.618 > [  4546][I][RFAL.cpp:48] dump_regs(): Reg[0x0F]:0x00:00000000
11:39:38.624 > [  4553][I][RFAL.cpp:48] dump_regs(): Reg[0x15]:0x00:00000000
11:39:38.631 > [  4559][I][RFAL.cpp:48] dump_regs(): Reg[0x28]:0x10:00010000
11:39:38.637 > [  4566][I][RFAL.cpp:48] dump_regs(): Reg[0x29]:0x7C:01111100
11:39:38.644 > [  4572][I][RFAL.cpp:48] dump_regs(): Reg[0x2A]:0x80:10000000
11:39:38.650 > [  4578][I][RFAL.cpp:48] dump_regs(): Reg[0x2B]:0x04:00000100
11:39:38.657 > [  4585][I][RFAL.cpp:48] dump_regs(): Reg[0x2C]:0xD0:11010000
11:39:38.663 > [  4591][I][RFAL.cpp:48] dump_regs(): Reg[0x30]:0x00:00000000
11:39:38.669 > [  4598][I][RFAL.cpp:48] dump_regs(): Reg[0x31]:0x00:00000000
11:39:38.676 > [  4604][I][RFAL.cpp:48] dump_regs(): Reg[0x32]:0x00:00000000
11:39:38.682 > [  4611][I][RFAL.cpp:48] dump_regs(): Reg[0x33]:0x00:00000000


---MINE
12:44:07.365 > [ 32199][I][unit_ST25R3916.cpp:669] dumpRegister(): SpaceA
12:44:07.371 > [ 32199][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X00]:0X00:00000000
12:44:07.378 > [ 32205][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X01]:0X98:10011000
12:44:07.385 > [ 32212][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X02]:0XC8:11001000
12:44:07.392 > [ 32219][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X03]:0X08:00001000
12:44:07.398 > [ 32225][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X04]:0X00:00000000
12:44:07.405 > [ 32232][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X05]:0X1C:00011100
12:44:07.412 > [ 32239][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X06]:0X00:00000000
12:44:07.418 > [ 32246][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X07]:0X00:00000000
12:44:07.425 > [ 32252][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X08]:0X00:00000000
12:44:07.432 > [ 32259][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X09]:0X00:00000000
12:44:07.438 > [ 32266][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0A]:0X80:10000000
12:44:07.445 > [ 32272][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0B]:0X13:00010011
12:44:07.452 > [ 32279][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0C]:0X2D:00101101
12:44:07.458 > [ 32286][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0D]:0X00:00000000
12:44:07.465 > [ 32292][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0E]:0X00:00000000
12:44:07.472 > [ 32299][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0F]:0X0C:00001100
12:44:07.478 > [ 32306][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X10]:0X04:00000100
12:44:07.485 > [ 32312][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X11]:0X23:00100011
12:44:07.492 > [ 32319][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X12]:0X00:00000000
12:44:07.498 > [ 32326][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X13]:0X00:00000000
12:44:07.505 > [ 32332][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X14]:0X00:00000000
12:44:07.512 > [ 32339][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X15]:0X80:10000000
12:44:07.518 > [ 32346][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X16]:0XFF:11111111
12:44:07.525 > [ 32352][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X17]:0XFF:11111111
12:44:07.532 > [ 32359][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X18]:0X00:00000000
12:44:07.539 > [ 32366][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X19]:0XFB:11111011
12:44:07.545 > [ 32373][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1A]:0X08:00001000
12:44:07.552 > [ 32379][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1B]:0X40:01000000
12:44:07.559 > [ 32386][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1C]:0X00:00000000
12:44:07.565 > [ 32393][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1D]:0X00:00000000
12:44:07.572 > [ 32399][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1E]:0X00:00000000
12:44:07.579 > [ 32406][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1F]:0X00:00000000
12:44:07.585 > [ 32413][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X20]:0X00:00000000
12:44:07.592 > [ 32419][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X21]:0X00:00000000
12:44:07.599 > [ 32426][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X22]:0X00:00000000
12:44:07.605 > [ 32433][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X23]:0X18:00011000
12:44:07.612 > [ 32439][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X24]:0X00:00000000
12:44:07.619 > [ 32446][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X25]:0X00:00000000
12:44:07.626 > [ 32453][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X26]:0X80:10000000
12:44:07.632 > [ 32459][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X27]:0X80:10000000
12:44:07.639 > [ 32466][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X28]:0XF0:11110000
12:44:07.645 > [ 32473][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X29]:0X60:01100000
12:44:07.652 > [ 32479][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2A]:0X33:00110011
12:44:07.659 > [ 32486][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2B]:0X22:00100010
12:44:07.666 > [ 32493][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2C]:0X00:00000000
12:44:07.672 > [ 32499][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2D]:0X00:00000000
12:44:07.679 > [ 32506][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2E]:0X00:00000000
12:44:07.686 > [ 32513][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2F]:0X00:00000000
12:44:07.692 > [ 32520][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X30]:0X00:00000000
12:44:07.699 > [ 32526][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X31]:0X10:00010000
12:44:07.706 > [ 32533][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X32]:0X00:00000000
12:44:07.712 > [ 32540][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X33]:0X00:00000000
12:44:07.719 > [ 32546][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X34]:0X00:00000000
12:44:07.726 > [ 32553][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X35]:0X00:00000000
12:44:07.732 > [ 32560][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X36]:0X00:00000000
12:44:07.739 > [ 32566][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X37]:0X00:00000000
12:44:07.746 > [ 32573][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X38]:0X00:00000000
12:44:07.752 > [ 32580][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X39]:0X00:00000000
12:44:07.759 > [ 32586][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3A]:0X00:00000000
12:44:07.766 > [ 32593][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3B]:0X00:00000000
12:44:07.772 > [ 32600][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3C]:0X00:00000000
12:44:07.779 > [ 32606][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3D]:0X00:00000000
12:44:07.786 > [ 32613][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3E]:0X00:00000000
12:44:07.792 > [ 32620][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3F]:0X2A:00101010
12:44:07.798 > [ 32626][I][unit_ST25R3916.cpp:694] dumpRegister(): SpaceB
12:44:07.804 > [ 32632][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X05]:0X00:00000000
12:44:07.811 > [ 32638][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X06]:0X00:00000000
12:44:07.818 > [ 32645][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0B]:0X0C:00001100
12:44:07.824 > [ 32652][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0C]:0X13:00010011
12:44:07.831 > [ 32658][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0D]:0X01:00000001
12:44:07.838 > [ 32665][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0F]:0X00:00000000
12:44:07.844 > [ 32672][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X15]:0X33:00110011
12:44:07.851 > [ 32678][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X28]:0X10:00010000
12:44:07.858 > [ 32685][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X29]:0X7C:01111100
12:44:07.865 > [ 32692][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2A]:0X00:00000000
12:44:07.871 > [ 32699][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2B]:0X04:00000100
12:44:07.878 > [ 32705][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2C]:0XF0:11110000
12:44:07.885 > [ 32712][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X30]:0X00:00000000
12:44:07.891 > [ 32719][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X31]:0X00:00000000
12:44:07.898 > [ 32725][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X32]:0X00:00000000
12:44:07.905 > [ 32732][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X33]:0X00:00000000


--To same
15:07:44.914 > DUMP:0x3fcebd59 3 bytes
15:07:44.914 > 0x3fcebd59| 26 01 00                                        |&..
15:07:44.920 > [  4504][E][unit_ST25R3916_nfcv.cpp:146] nfcvTransceive(): Timeout
15:07:44.921 > [  4622][E][Detect.cpp:117] loop(): ERROR
15:07:44.926 > [  4505][I][unit_ST25R3916.cpp:669] dumpRegister(): SpaceA
15:07:44.933 > [  4510][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X00]:0X07:00000111
15:07:44.940 > [  4517][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X01]:0X3C:00111100
15:07:44.946 > [  4523][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X02]:0XCB:11001011
15:07:44.953 > [  4530][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X03]:0X70:01110000
15:07:44.960 > [  4537][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X04]:0X00:00000000
15:07:44.966 > [  4544][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X05]:0X00:00000000
15:07:44.973 > [  4550][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X06]:0X00:00000000
15:07:44.980 > [  4557][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X07]:0X00:00000000
15:07:44.986 > [  4564][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X08]:0X5D:01011101
15:07:44.993 > [  4570][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X09]:0X38:00111000
15:07:45.000 > [  4577][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0A]:0X01:00000001
15:07:45.006 > [  4584][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0B]:0X13:00010011
15:07:45.013 > [  4590][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0C]:0X2D:00101101
15:07:45.020 > [  4597][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0D]:0X00:00000000
15:07:45.026 > [  4604][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0E]:0X00:00000000
15:07:45.033 > [  4610][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X0F]:0X41:01000001
15:07:45.040 > [  4617][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X10]:0X04:00000100
15:07:45.046 > [  4624][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X11]:0X23:00100011
15:07:45.053 > [  4630][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X12]:0X20:00100000
15:07:45.060 > [  4637][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X13]:0X01:00000001
15:07:45.066 > [  4644][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X14]:0X84:10000100
15:07:45.073 > [  4650][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X15]:0X80:10000000
15:07:45.080 > [  4657][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X16]:0X85:10000101
15:07:45.087 > [  4664][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X17]:0XA7:10100111
15:07:45.093 > [  4671][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X18]:0X0F:00001111
15:07:45.100 > [  4677][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X19]:0X7B:01111011
15:07:45.107 > [  4684][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1A]:0X00:00000000
15:07:45.113 > [  4691][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1B]:0X00:00000000
15:07:45.120 > [  4697][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1C]:0X00:00000000
15:07:45.127 > [  4704][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1D]:0X00:00000000
15:07:45.133 > [  4711][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1E]:0X00:00000000
15:07:45.140 > [  4717][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X1F]:0X00:00000000
15:07:45.147 > [  4724][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X20]:0X00:00000000
15:07:45.153 > [  4731][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X21]:0X00:00000000
15:07:45.160 > [  4737][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X22]:0X00:00000000
15:07:45.167 > [  4744][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X23]:0X18:00011000
15:07:45.173 > [  4751][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X24]:0X00:00000000
15:07:45.180 > [  4757][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X25]:0X00:00000000
15:07:45.187 > [  4764][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X26]:0X82:10000010
15:07:45.194 > [  4771][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X27]:0X82:10000010
15:07:45.200 > [  4777][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X28]:0X70:01110000
15:07:45.207 > [  4784][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X29]:0X5F:01011111
15:07:45.214 > [  4791][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2A]:0X13:00010011
15:07:45.220 > [  4798][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2B]:0X02:00000010
15:07:45.227 > [  4804][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2C]:0X00:00000000
15:07:45.234 > [  4811][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2D]:0X00:00000000
15:07:45.240 > [  4818][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2E]:0X10:00010000
15:07:45.247 > [  4824][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X2F]:0X00:00000000
15:07:45.254 > [  4831][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X30]:0X00:00000000
15:07:45.260 > [  4838][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X31]:0X10:00010000
15:07:45.267 > [  4844][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X32]:0X00:00000000
15:07:45.274 > [  4851][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X33]:0X00:00000000
15:07:45.280 > [  4858][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X34]:0X00:00000000
15:07:45.287 > [  4864][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X35]:0X00:00000000
15:07:45.294 > [  4871][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X36]:0X00:00000000
15:07:45.300 > [  4878][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X37]:0X00:00000000
15:07:45.307 > [  4884][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X38]:0X00:00000000
15:07:45.314 > [  4891][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X39]:0X00:00000000
15:07:45.321 > [  4898][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3A]:0X00:00000000
15:07:45.327 > [  4904][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3B]:0X00:00000000
15:07:45.334 > [  4911][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3C]:0X00:00000000
15:07:45.341 > [  4918][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3D]:0X00:00000000
15:07:45.347 > [  4924][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3E]:0X00:00000000
15:07:45.354 > [  4931][I][unit_ST25R3916.cpp:673] dumpRegister(): Reg[0X3F]:0X2A:00101010
15:07:45.359 > [  4938][I][unit_ST25R3916.cpp:694] dumpRegister(): SpaceB
15:07:45.366 > [  4943][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X05]:0X00:00000000
15:07:45.372 > [  4950][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X06]:0X00:00000000
15:07:45.379 > [  4956][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0B]:0X0C:00001100
15:07:45.386 > [  4963][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0C]:0X13:00010011
15:07:45.392 > [  4970][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0D]:0X01:00000001
15:07:45.399 > [  4976][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X0F]:0X00:00000000
15:07:45.406 > [  4983][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X15]:0X33:00110011
15:07:45.413 > [  4990][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X28]:0X10:00010000
15:07:45.419 > [  4997][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X29]:0X7C:01111100
15:07:45.426 > [  5003][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2A]:0X00:00000000
15:07:45.433 > [  5010][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2B]:0X04:00000100
15:07:45.439 > [  5017][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X2C]:0XF0:11110000
15:07:45.446 > [  5023][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X30]:0X00:00000000
15:07:45.453 > [  5030][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X31]:0X00:00000000
15:07:45.459 > [  5037][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X32]:0X00:00000000
15:07:45.466 > [  5043][I][unit_ST25R3916.cpp:698] dumpRegister(): Reg[0X33]:0X00:00000000
*/
