/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfca.cpp
  @brief class UnitST25R3916 implementation for NFC-A
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>
#include <esp_random.h>

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

// clang-format off
#pragma GCC optimize("O3")
// clang-format on

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::A)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace {
void suc_23(const uint32_t Nt, uint32_t& suc2, uint32_t& suc3)
{
    m5::utility::FibonacciLFSR_Right<32, 16, 14, 13, 11> tmp(Nt);
    tmp.next32();
    tmp.next32();
    suc2 = tmp.next32();
    suc3 = tmp.next32();
}

uint64_t key_to64(const uint8_t k[6])
{
    uint64_t v{};
    v |= (uint64_t)k[0] << 40;
    v |= (uint64_t)k[1] << 32;
    v |= (uint64_t)k[2] << 24;
    v |= (uint64_t)k[3] << 16;
    v |= (uint64_t)k[4] << 8;
    v |= (uint64_t)k[5] << 0;
    return v;
}

uint32_t array_to32(const uint8_t a[4])
{
    uint32_t v{};
    v |= (uint32_t)a[0] << 24;
    v |= (uint32_t)a[1] << 16;
    v |= (uint32_t)a[2] << 8;
    v |= (uint32_t)a[3] << 0;
    return v;
}

// < 32bits
void append_parity(uint8_t* out, const uint32_t out_len, const uint8_t* in, const uint32_t in_len,
                   const uint32_t parity)
{
    const uint32_t required_size = (in_len * 9 + 7) >> 3;
    if (out_len < required_size) {
        M5_LIB_LOGD("Not enough out %u/%u", out_len, required_size);
        return;
    }

    uint32_t bitpos{};
    for (uint32_t i = 0; i < in_len; ++i) {
        uint8_t v = in[i];
        // Copy bits
        for (int k = 0; k < 8; ++k) {
            uint8_t b = (v >> k) & 1u;
            if (b) {
                uint32_t byte = bitpos >> 3;
                uint8_t off   = bitpos & 7;
                out[byte] |= (1u << off);
            }
            ++bitpos;
        }
        // Append  parity
        uint8_t pb = (parity >> i) & 1u;
        if (pb) {
            uint32_t byte = bitpos >> 3;
            uint8_t off   = bitpos & 7;
            out[byte] |= (1u << off);
        }
        ++bitpos;
    }
}

constexpr uint8_t val_table[] = {

    0x07, 0x3C, 0x03, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x00, 0x00, 0x08, 0x2D, 0xD8, 0x00, 0x02,
    0x00, 0x00, 0x08, 0x00, 0x00, 0x80, 0x5F, 0xE6, 0x0F, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC5, 0x00, 0xFF, 0x70, 0x5F, 0x13, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

};

inline uint32_t OCB(const uint8_t c)
{
    // printf("%08o", OCB(0x2d)); => 00101101
    return (c & 1) | (c & 2) << 2 | (c & 4) << 4 | (c & 8) << 6 | (c & 16) << 8 | (c & 32) << 10 | (c & 64) << 12 |
           (c & 128) << 14;
}

}  // namespace

namespace m5 {
namespace unit {
// -------------------------------- For NFC-A
bool UnitST25R3916::configure_nfc_a()
{
    _encrypted = false;

    if (!writeInitiatorOperationMode(InitiatorOperationMode::ISO14443A, nfc_ar8_auto /* 0x01 */) ||  //
        !writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K) ||                                         //
        !writeSettingsISO14443A(0x00)) {
        return false;
    }

    clear_bit_register8(REG_AUXILIARY_DEFINITION, dis_corr);
    writeOvershootProtectionConfiguration1(0x40);
    writeOvershootProtectionConfiguration2(0x03);
    writeUndershootProtectionConfiguration1(0x40);
    writeUndershootProtectionConfiguration2(0x03);

    writeCorrelatorConfiguration1(0x47);
    writeCorrelatorConfiguration2(0x00);

#if 1
    // Sensitivity Priority
    constexpr uint8_t recv_3{0x00};
    constexpr uint8_t recv_4{0x00};
#else
    // Stability-focused
    constexpr uint8_t recv_3{0xD8};
    constexpr uint8_t recv_4{0x22};
    // Intermediate Settings
    constexpr uint8_t recv_3{0x80};
    constexpr uint8_t recv_4{0x11};
#endif

    enable_interrupts(I_wl32 | I_txe32 | I_rxs32 | I_rxe32 | I_par32 | I_crc32 | I_err132 | I_err232 | I_nre32 |
                      I_col32);

    return writeReceiverConfiguration1(z_600k) &&                              // z600k
           writeReceiverConfiguration2(sqm_dyn | agc_en | agc_m | agc6_3) &&   //
           writeReceiverConfiguration3(recv_3) &&                              // rx gain
           writeReceiverConfiguration4(recv_4) &&                              // rx gain
           writeDirectCommand(CMD_RESET_RX_GAIN) && writeMaskInterrupts(0) &&  //
           nfc_initial_field_on();
}

bool UnitST25R3916::configure_emulation_a()
{
    _encrypted = false;

    writeModeDefinition(0xC8);                 // target, NFC-A, Bit rate detection mode
    writeNFCIP1PassiveTargetDefinition(0x5C);  // fdel[7:4], disable d_ac_ap2p.d_214/424_1r, enable d_106_ac
    writeMaskPassiveTargetInterrupt(0x02);     // mask I_wu_ax
    writeTimerAndEMVControl(0x08);             // mrt_setp 512

#if 0
    uint8_t reg = 0x00;
    for (auto&& v : val_table) {
        uint8_t rv{};
        read_register8(reg, rv);
        if(rv != v){
            M5_LIB_LOGD("[%02X]:%02X/%02X %08o/%08o", reg, rv,v, OCB(rv), OCB(v));
            write_register8(reg, v);
        }
        ++reg;
    }

    {
        uint16_t r{};
        r = 0x05;
        writeRegister8(r, 0x40);
        r = 0x06;
        writeRegister8(r, 0x00);
        r = 0x0B;
        writeRegister8(r, 0x0C);
        r = 0x0C;
        writeRegister8(r, 0x93);
        r = 0x0D;
        writeRegister8(r, 0x00);
        r = 0x0F;
        writeRegister8(r, 0x00);
        r = 0x15;
        writeRegister8(r, 0x33);
        r = 0x28;
        writeRegister8(r, 0x10);
        r = 0x29;
        writeRegister8(r, 0x7C);
        r = 0x2A;
        writeRegister8(r, 0x80);
        r = 0x2B;
        writeRegister8(r, 0x04);
        r = 0x2C;
        writeRegister8(r, 0xB0);
    }
#endif

    return true;
}

uint32_t UnitST25R3916::nfcaTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                       const uint32_t timeout_ms)
{
    if (!nfcaTransmit(tx, tx_len, timeout_ms)) {
        M5_LIB_LOGE("nfcaTransmit FAILED tx_len=%u", tx_len);
        return false;
    }
    M5_LIB_LOGD("nfcaTransmit OK tx_len=%u", tx_len);
    return nfcaReceive(rx, rx_len, timeout_ms);
}

bool UnitST25R3916::nfcaTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    if (!tx || !tx_len) {
        return false;
    }

    if ((timeout_ms ? !write_fwt_timer(timeout_ms) : false) ||                                                      //
        !writeSettingsISO14443A(0x00 /*standard*/) || !clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) ||  //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(tx, tx_len) ||                      //
        !writeNumberOfTransmittedBytes(tx_len, 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        M5_LIB_LOGE("nfcaTransmit failed tx_len=%u timeout_ms=%u", tx_len, timeout_ms);
        return false;
    }
    return true;
}

bool UnitST25R3916::nfcaReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    CHECK_MODE();

    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org) {
        return false;
    }

    if (!wait_for_FIFO(timeout_ms, rx_len_org)) {
        M5_LIB_LOGE("nfcaReceive timeout rx_len=%u timeout_ms=%u", rx_len_org, timeout_ms);
        M5_LIB_LOGD("Timeout");
        return false;
    }

    uint16_t actual{};
    auto bb = readFIFO(actual, rx, rx_len_org);
    if (!bb) {
        M5_LIB_LOGE("Failed to readFIFO %u/%u", actual, rx_len_org);
        return false;
    }

    // Check NACK
    uint16_t bytes = bb & 0xffff;
    uint16_t bits  = (bb >> 16) & 0xFF;
    M5_LIB_LOGV("readFIFO %u/%u %u/%u %02X", actual, rx_len_org, bb >> 16, bb & 0xFFFF, rx[0]);
    rx_len = actual;
    return (bytes == 1 && bits == 4) ? rx[0] == ACK_NIBBLE : true;
}

bool UnitST25R3916::nfca_request_wakeup(uint16_t& atqa, const bool request)
{
    CHECK_MODE();

    _encrypted = false;
    atqa       = 0;

    // REQA or WUPA (Receive without CRC)
    if (!write_fwt_timer(TIMEOUT_REQ_WUP) ||  //
        !writeSettingsISO14443A(antcl) || !set_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||
        !writeDirectCommand(request ? CMD_TRANSMIT_REQA : CMD_TRANSMIT_WUPA)) {
        M5_LIB_LOGD("Failed to %s", request ? "REQA" : "WUPA");
        return false;
    }

    auto irq = wait_for_interrupt(I_rxe32 | I_rxs32 | I_col32, TIMEOUT_REQ_WUP);
    // M5_LIB_LOGD("IRQ:%08X", irq);

    if (!is_irq32_rxe(irq) && is_irq32_rxs(irq)) {
        auto timeout_at = m5::utility::millis() + TIMEOUT_REQ_WUP;
        uint16_t bytes{};
        uint8_t bits{};
        do {
            if (readFIFOSize(bytes, bits) && bytes >= 2) {
                break;
            }
            std::this_thread::yield();
        } while (m5::utility::millis() <= timeout_at);
        readFIFOSize(bytes, bits);
        irq |= bytes ? I_rxe32 : 0u;
    }

    if (is_irq32_rxe(irq)) {
        // ATQA
        uint8_t rbuf[2]{};
        uint16_t actual{};
        if (readFIFO(actual, rbuf, sizeof(rbuf)) && actual == 2) {
            atqa = ((uint16_t)rbuf[1] << 8) | (uint16_t)rbuf[0];
            // M5_LIB_LOGD("ATQA:%04X %u", atqa, actual);
            //  When ocuur collisions, the ATQA value is inaccurate
            return true;
        }
        return false;
    }

    // M5_LIB_LOGD("Error: %08X", irq);
    return false;
}

bool UnitST25R3916::nfca_anti_collision(uint8_t rbuf[5], const uint8_t lv)
{
    if (!rbuf || lv < 1 || lv > 3) {
        return false;
    }

    // ANTICOLL/SEL
    if (!write_fwt_timer(TIMEOUT_ANTICOLL) ||  //
        !writeSettingsISO14443A(antcl) || !clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx)) {
        return false;
    }

    uint8_t anticoll_frame[7 /* SELn + NVB + CL4 + bits*/] = {
        (uint8_t)(0x91 + lv * 2),  // SELn
        0x20                       // NVB
    };
    uint32_t sbytes{2}, sbits{};
    uint8_t rbuf_offset{};
    uint32_t count{32};  // Max loop count
    bool collision{};
    uint16_t actual{};
    uint8_t coll_byte{1};

    do {
        if (!clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||
            !writeFIFO(anticoll_frame, sbytes + (sbits != 0)) || !writeNumberOfTransmittedBytes(sbytes, sbits) ||
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            return false;
        }

        auto irq  = wait_for_interrupt(I_rxe32 | I_col32, TIMEOUT_ANTICOLL);
        collision = is_irq32_collision(irq);
        if ((!collision && !is_irq32_rxe(irq))) {
            M5_LIB_LOGD("Failed Lv::%u col:%u %08X", lv, collision, irq);
            return false;
        }
        uint8_t cd{};
        if (!readFIFO(actual, rbuf + rbuf_offset, 5 - rbuf_offset) || !actual || !readCollisionDisplay(cd)) {
            return false;
        }

        // OCCUR collision
        if (collision) {
            M5_LIB_LOGD("Colliion");
            uint8_t cbytes = ((cd >> 4) & 0x0F);  // c_byte[3:0]
            uint8_t cbits  = ((cd >> 1) & 0x07);  // c_bit[2:0]
            if (actual) {
                coll_byte = rbuf[rbuf_offset + actual - 1];  // from LSB
                coll_byte |= 1U << cbits;
            }
            M5_LIB_LOGD("   COL:%u bytes, %u bits", cbytes, cbits);
            M5_LIB_LOGD("   coll_byte: %02x", coll_byte);

            sbytes            = cbytes + (cbits == 0x07);
            sbits             = (cbits + 1) & 0x07;
            anticoll_frame[1] = (sbytes << 4) | sbits;  // NVB
            memcpy(anticoll_frame + 2 + rbuf_offset, rbuf + rbuf_offset, actual);
            anticoll_frame[sbytes] = coll_byte;
            rbuf_offset            = actual - 1;
        }

        // Store completed bytes
        if (sbits) {
            rbuf[rbuf_offset] >>= sbits;
            rbuf[rbuf_offset] <<= sbits;
            rbuf[rbuf_offset] |= coll_byte;
        }
    } while (collision && count--);
    return !collision;
}

bool UnitST25R3916::nfcaSelectWithAnticollision(bool& completed, PICC& picc, const uint8_t lv)
{
    completed  = false;
    _encrypted = false;

    CHECK_MODE();

    if (lv < 1 || lv > 3) {
        return false;
    }

    // Resolve collision
    uint8_t rbuf[5]{};
    if (!nfca_anti_collision(rbuf, lv)) {
        return false;
    }

    // Copy PICC
    memcpy(picc.uid + (lv - 1) * 3, rbuf + (rbuf[0] == 0x88), 4 - (rbuf[0] == 0x88));

    uint8_t select_frame[7] = {(uint8_t)(0x91 + lv * 2), 0x70};
    memcpy(select_frame + 2, rbuf, sizeof(rbuf));

    // Select
    uint16_t rx_len{3};
    if (!nfcaTransceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
        M5_LIB_LOGD("Failed to select");
        return false;
    }

    uint8_t sak = rbuf[0];
    // M5_LIB_LOGD(">>>> SAK:%02X (%u, %u)  %u ",  //
    //            sak, is_sak_completed(sak), is_sak_completed_14443_4(sak), sak_to_type(sak));

    //   Completed?
    if (is_sak_completed_14443_4(sak)) {
        picc.size = 1 + lv * 3;
        picc.sak  = sak;
        picc.type =
            Type::ISO_14443_4;  // WARNING: This is a preliminary diagnosis; a more accurate diagnosis is required
        picc.blocks = get_number_of_blocks(picc.type);
        completed   = true;
        return true;
    } else if (is_sak_completed(sak)) {
        picc.size = 1 + lv * 3;
        picc.sak  = sak;
        picc.type =
            sak_to_type(sak);  // WARNING: This is a preliminary diagnosis; a more accurate diagnosis is required
        // Only the Plus X SL2 can be confirmed with sak
        if (picc.type == Type::MIFARE_Plus_2K || picc.type == Type::MIFARE_Plus_4K) {
            picc.sub_type_plus  = SubTypePlus::X;
            picc.security_level = 2;
        }
        picc.blocks = get_number_of_blocks(picc.type);
        completed   = true;
    }
    // M5_LIB_LOGD(">>>> Select %02X %u %u", sak, completed, has_sak_dependent_bit(sak));
    return completed || has_sak_dependent_bit(sak);  // completed or continue
}

bool UnitST25R3916::nfcaSelect(const PICC& picc)
{
    _encrypted = false;

    CHECK_MODE();

    // Select even if picc is not valid

    bool completed{};
    uint8_t select_frame[7] = {0x93, 0x70};
    uint8_t rbuf[3]{};
    uint8_t lv{1};
    uint8_t offset{};

    if (!writeSettingsISO14443A(0x00 /*standard*/) || !clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx)) {
        M5_LIB_LOGD("Failed to settings");
        return false;
    }

    do {
        select_frame[0] = 0x91 + lv * 2;
        // Build frame
        if (picc.size > lv * 3 + 1) {
            select_frame[2] = 0x88;
        } else {
            select_frame[2] = picc.uid[offset++];
        }
        select_frame[3] = picc.uid[offset++];
        select_frame[4] = picc.uid[offset++];
        select_frame[5] = picc.uid[offset++];
        select_frame[6] = calculate_bcc8(select_frame + 2, 4);

        // Select
        uint16_t rx_len{3};
        if (!nfcaTransceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
            M5_LIB_LOGD("Failed to select");
            return false;
        }
        completed = is_sak_completed(rbuf[0]) || is_sak_completed_14443_4(rbuf[0]);

        ++lv;
    } while (!completed && lv < 4);
    // M5_LIB_LOGD("   >>>> SELECT Result:%u", completed);

    return completed;
}

bool UnitST25R3916::nfcaHlt()
{
    CHECK_MODE();

    _encrypted = false;

    const uint8_t hlt_frame[2] = {m5::stl::to_underlying(Command::HLTA), 0x00};

    if (_encrypted) {
        if (!write_fwt_timer(TIMEOUT_HALT) || !mifare_classic_send_encrypt(hlt_frame, sizeof(hlt_frame))) {
            return false;
        }
    } else {
        if (!write_fwt_timer(TIMEOUT_HALT) ||  //
            !writeSettingsISO14443A(0x00 /*standard*/) ||
            !clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) ||                                         //
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
            !writeFIFO(hlt_frame, sizeof(hlt_frame)) || !writeNumberOfTransmittedBytes(sizeof(hlt_frame), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
            M5_LIB_LOGD("Failed to hlt");
            return false;
        }
    }
    // No response is coming back, so need to confirm if it was sent
    auto irq = wait_for_interrupt(I_txe32, TIMEOUT_HALT);
    return is_irq32_txe(irq);
}

bool UnitST25R3916::nfcaReadBlock(uint8_t rx[16], const uint8_t addr)
{
    CHECK_MODE();

    if (!rx) {
        return false;
    }
    uint16_t rx_len{16};
    uint8_t cmd[2] = {m5::stl::to_underlying(Command::READ), addr};
    if (_encrypted) {
        return mifare_classic_transceive_encrypt(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ, true, true);
    }
    return nfcaTransceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ);
}

bool UnitST25R3916::nfcaWriteBlock(const uint8_t addr, const uint8_t tx[16])
{
    CHECK_MODE();

    if (!tx) {
        return false;
    }

    uint8_t buf[16 + 2 /*CRC*/]{};
    memcpy(buf, tx, 16);
    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    auto crc = crc16.range(buf, 16);
    buf[16]  = crc & 0xFF;
    buf[17]  = crc >> 8;

    uint8_t cmd[2] = {m5::stl::to_underlying(Command::WRITE_BLOCK), addr};
    uint8_t rx[1]{};  // 4bit ACK
    uint16_t rx_len{1};

    if (_encrypted) {
        if (mifare_classic_transceive_encrypt(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_WRITE1, false, true) &&
            rx[0] == ACK_NIBBLE) {
            rx_len = 1;
            if (mifare_classic_transceive_encrypt(rx, rx_len, tx, 16, TIMEOUT_WRITE2, false, true) &&
                rx[0] == ACK_NIBBLE) {
                return true;
            }
            M5_LIB_LOGD("Faile to WRITE2");
            return false;
        } else {
            M5_LIB_LOGD("Faile to WRITE1");
            return false;
        }
    }

    //
    if (nfcaTransceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_WRITE1) && rx[0] == ACK_NIBBLE) {
        rx_len = 1;
        if (nfcaTransceive(rx, rx_len, buf, sizeof(buf), TIMEOUT_WRITE2) && rx[0] == ACK_NIBBLE) {
            return true;
        }
    }
    M5_LIB_LOGD("Faile to WRITE");
    return false;
}

// -------------------------------- For MIFARE classic
bool UnitST25R3916::mifare_classic_send_encrypt(const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || tx_len > MIFARE_CLASSIC_MAX_TX_LEN) {
        return false;
    }

    // Send
    uint8_t tmp_tx[MIFARE_CLASSIC_MAX_TX_WITH_CRC]{};
    memcpy(tmp_tx, tx, tx_len);

    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    auto crc           = crc16.range(tx, tx_len);
    tmp_tx[tx_len]     = crc & 0xFF;
    tmp_tx[tx_len + 1] = crc >> 8;

    uint8_t enc_tx[MIFARE_CLASSIC_MAX_TX_WITH_CRC]{};
    const uint16_t tx_with_crc = tx_len + 2;
    uint32_t parity            = _crypto1.encrypt(enc_tx, tmp_tx, tx_with_crc);

    uint16_t total_bits    = 9 * tx_with_crc;
    uint16_t bitstream_len = (total_bits + 7) >> 3;

    uint8_t bitstream[MIFARE_CLASSIC_MAX_BITSTREAM_LEN]{};
    append_parity(bitstream, bitstream_len, enc_tx, tx_with_crc, parity);

    uint8_t sbytes = total_bits >> 3;
    uint8_t sbits  = total_bits & 0x07;

    if (!writeSettingsISO14443A(no_tx_par) ||                                                     //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                              //
        !writeFIFO(bitstream, bitstream_len) || !writeNumberOfTransmittedBytes(sbytes, sbits) ||  //
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGD("Failed to send");
        return false;
    }
    return true;
}

bool UnitST25R3916::mifare_classic_transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx,
                                                      const uint16_t tx_len, const uint32_t timeout_ms,
                                                      const bool include_crc, const bool decrypt)
{
    if (!rx || !rx_len || !tx || !tx_len || tx_len > MIFARE_CLASSIC_MAX_TX_LEN || rx_len > MIFARE_CLASSIC_MAX_RX_LEN) {
        return false;
    }

    // Send
    if (!set_bit_register8(REG_AUXILIARY_DEFINITION, (include_crc ? no_crc_rx : 0)) ||
        !mifare_classic_send_encrypt(tx, tx_len)) {
        M5_LIB_LOGD("SEND ERROR");
        return false;
    }

    // Read
    const uint32_t rlen = rx_len + (include_crc ? 2 : 0 /* CRC */);
    if (rlen > MIFARE_CLASSIC_MAX_RX_WITH_CRC) {
        return false;
    }

    if (!wait_for_FIFO(timeout_ms, rlen)) {
        M5_LIB_LOGD("Timeout");
        return false;
    }

    uint8_t rbuf[MIFARE_CLASSIC_MAX_RX_WITH_CRC]{};
    uint16_t actual{};
    if (!readFIFO(actual, rbuf, rlen) || actual != rlen) {
        M5_LIB_LOGD("Failed to readFIFO %u/%u", actual, rlen);
        M5_DUMPE(rbuf, actual);
        return false;
    }

    // M5_LIB_LOGD("read: %u/%u", actual, rlen);

    // Decryption
    if (decrypt) {
        if (actual == 1) {  // 4bit ACK
            uint8_t ret = rbuf[0] & 0x0F;
            uint8_t res{};
            res |= (_crypto1.step_with(0) ^ ((ret >> 0) & 1)) << 0;
            res |= (_crypto1.step_with(0) ^ ((ret >> 1) & 1)) << 1;
            res |= (_crypto1.step_with(0) ^ ((ret >> 2) & 1)) << 2;
            res |= (_crypto1.step_with(0) ^ ((ret >> 3) & 1)) << 3;
            rbuf[0] = res;
            if (res != ACK_NIBBLE) {
                M5_LIB_LOGD("NACK:%02X", res);
                return false;
            }
        } else {
            for (uint_fast8_t i = 0; i < actual; ++i) {
                rbuf[i] ^= _crypto1.step8(0);
            }
        }
    }

    if (include_crc) {
        m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
        uint16_t crc = crc16.range(rbuf, rx_len);
        if ((crc & 0xFF) != rbuf[rlen - 2] || ((crc >> 8) != rbuf[rlen - 1])) {
            M5_LIB_LOGD("CRC ERROR: C:%04x R:%02x%02x", crc, rbuf[rlen - 2], rbuf[rlen - 1]);
            return false;
        }
    }
    actual = std::min<uint16_t>(actual - (include_crc ? 2 : 0), rx_len);
    memcpy(rx, rbuf, actual);

    // M5_LIB_LOGD("copy: %u/%u", actual, rx_len);

    return true;
}

bool UnitST25R3916::mifare_classic_authenticate(const Command cmd, const PICC& picc, const uint8_t block,
                                                const Key& mkey)
{
    CHECK_MODE();

    if ((cmd != Command::AUTH_WITH_KEY_A && cmd != Command::AUTH_WITH_KEY_B) ||
        (!picc.isMifareClassic() && picc.isMifarePlus())) {
        return false;
    }

    M5_LIB_LOGV("AUTH:%02X %u %02X:%02X:%02X:%02X:%02X:%02X", cmd, block,  //
                mkey[0], mkey[1], mkey[2], mkey[3], mkey[4], mkey[5]);

    // 3-pass mutual authentication
    const uint64_t key48 = key_to64(mkey.data());

    // 1) Send AUTH command and receive token RB (Nt)
    uint8_t auth_frame[2] = {m5::stl::to_underlying(cmd), block};
    uint8_t RB[4]{};
    uint16_t rlen{4};

    if (_encrypted) {
        if (!mifare_classic_transceive_encrypt(RB, rlen, auth_frame, sizeof(auth_frame), TIMEOUT_AUTH1, false, false)) {
            M5_LIB_LOGD("Failed to send AUTH1(encrypt) %u", rlen);
            return false;
        }
    } else {
        if (!nfcaTransceive(RB, rlen, auth_frame, sizeof(auth_frame), TIMEOUT_AUTH1)) {
            M5_LIB_LOGD("Failed to send AUTH1(plain) %u", rlen);
            return false;
        }
    }
    m5::utility::delayMicroseconds(87);  // Wait for AUTH <-> Send AB (At least 86.4 us)

    // 2) Send encrypt token AB (Nr, Ar)
    uint8_t tail4[4]{};
    picc.tail4(tail4);
    const uint32_t u32 = array_to32(tail4);
    uint32_t Nt        = array_to32(RB);
    const uint32_t Nr  = esp_random();  // Change another RNG engine if you want
    uint32_t Ar{}, suc3{};
    uint8_t AB[8]{};
    uint8_t parity{};
    uint8_t bitstream[9 /* AB 8bytes + encrypt parity 1(8bits)] */]{};

    // M5_LIB_LOGD("Nt:%08X", Nt);

    _crypto1.init(key48);
    if (!_encrypted) {
        (void)_crypto1.inject(u32, Nt, false);
    } else {
        Nt = _crypto1.inject(u32, Nt, true) ^ Nt;
    }
    suc_23(m5::stl::byteswap(Nt), Ar /* == suc2 */, suc3);

    M5_LIB_LOGV("Auth:%u  mkey:%llX uid:%X Nt:%X Nr:%X Ar:%X suc3:%X", block, key48, u32, Nt, Nr, Ar, suc3);

    parity = _crypto1.encrypt(AB, Nr, Ar);
    append_parity(bitstream, sizeof(bitstream), AB, sizeof(AB), parity);

    writeDirectCommand(CMD_RESET_RX_GAIN);

    if (!write_fwt_timer(TIMEOUT_AUTH2) ||                                                                   //
        !writeSettingsISO14443A(no_tx_par) || !set_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) ||     //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
        !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGD("Failed to AUTH2(encrypt)");
        return false;
    }
    if (!wait_for_FIFO(TIMEOUT_AUTH2, 4)) {
        M5_LIB_LOGD("Timeout AUTH2");
        return false;
    }

    // 3) Receive token BA (At)
    uint8_t BA[4]{};
    uint16_t actual{};
    if (!readFIFO(actual, BA, sizeof(BA)) || actual != 4) {
        M5_LIB_LOGD("Failed to readFIFO AUTH2 %u", actual);
        return false;
    }

    uint8_t At2[4]{};
    for (int i = 0; i < 4; ++i) {  // Decrypt
        At2[i] = BA[i] ^ _crypto1.step8(0);
    }
    uint32_t At32 = (uint32_t)At2[0] | ((uint32_t)At2[1] << 8) | ((uint32_t)At2[2] << 16) | ((uint32_t)At2[3] << 24);
    _encrypted    = (At32 == suc3);

    return _encrypted;
}

bool UnitST25R3916::mifareClassicValueBlock(const m5::nfc::a::Command cmd, const uint8_t block, const uint32_t arg)
{
    CHECK_MODE();

    if (cmd != Command::DECREMENT && cmd != Command::INCREMENT && cmd != Command::RESTORE && cmd != Command::TRANSFER) {
        return false;
    }

    uint8_t cmd_frame[2] = {m5::stl::to_underlying(cmd), block};
    uint8_t rx[1]{};
    uint16_t rx_len{1};

    M5_LIB_LOGV("ValuBlock:%02X %u %u", cmd, block, arg);

    if (!mifare_classic_transceive_encrypt(                                                 //
            rx, rx_len, cmd_frame, sizeof(cmd_frame), TIMEOUT_VALUE_BLOCK, false, true) ||  //
        rx[0] != ACK_NIBBLE) {
        M5_LIB_LOGD("Failed to command %02X %u %u %02X", cmd, block, arg, rx[0]);
        return false;
    }
    if (cmd == Command::TRANSFER) {
        return true;
    }

    m5::utility::delayMicroseconds(82);  // Wait for command <-> Send (At least 82 us)

    uint8_t arg8[4]{};
    arg8[0] = arg & 0xFF;
    arg8[1] = arg >> 8;
    arg8[2] = arg >> 16;
    arg8[3] = arg >> 24;
    if (!clear_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx) || !mifare_classic_send_encrypt(arg8, sizeof(arg8))) {
        M5_LIB_LOGD("Failed to send");
        return false;
    }
    return !wait_for_FIFO(TIMEOUT_VALUE_BLOCK);  // Consider the timeout a success
}

}  // namespace unit
}  // namespace m5
