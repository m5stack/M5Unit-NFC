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

using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

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
        M5_LIB_LOGE("Not enough out %u/%u", out_len, required_size);
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
}  // namespace

namespace m5 {
namespace unit {

// -------------------------------- For NFC-A
bool UnitST25R3916::nfca_transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                    const uint32_t timeout_ms)
{
    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org || !tx || !tx_len) {
        return false;
    }

    if ((timeout_ms ? !write_noresponse_timeout(timeout_ms) : false) ||                //
        !writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) ||  //
        //        !writeMaskMainInterrupt(~I_rxe) || !writeMaskTimerAndNFCInterrupt(~I_nre) ||//
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(tx, tx_len) ||
        !writeNumberOfTransmittedBytes(tx_len, 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }

    if (!wait_for_FIFO(timeout_ms, rx_len_org)) {
        M5_LIB_LOGE("Timeout");
        // >>>>>>>>>
        if (tx) {
            m5::utility::log::dump(tx, tx_len, false);
        }
        return false;
    }

    uint16_t actual{};
    if (readFIFO(actual, rx, rx_len_org)) {
        rx_len = actual;
        return true;
    }
    M5_LIB_LOGE("Failed to readFIFO");
    return false;
}

Type UnitST25R3916::nfca_identify_type(const UID& uid)
{
    const uint8_t sak = uid.sak;

    if (sak & 0x02 /*b2*/) {  // RFU?
        return Type::Unknown;
    }
    if (sak & 0x04 /*b3*/) {  // UID uncompleted
        return Type::Unknown;
    }

    if (sak & 0x08 /*b4*/) {
        // Bit 4 Yes
        if (sak & 0x10 /*b5*/) {
            // Bit 5 Yes
            if (sak & 0x01 /*b1*/) {
                return Type::MIFARE_Classic_2K;  // 0x19
            }
            if (sak & 0x20 /*b6*/) {
                return Type::MIFARE_Classic_4K;  // 0x38 SmartMX with
            }
            // RATS?
            if (true) {
                return Type::MIFARE_Classic_4K;  // 0x18
            }
            // PlusEV1, PlusS, PlusX (SL1)
            return Type::Unknown;
        }
        // Bit 5 No
        if (sak & 0x01 /*b1*/) {
            // MIFARE Mini
            return Type::Unknown;  // 0x09
        }
        if (sak & 0x20 /*b6*/) {
            return Type::MIFARE_Classic_1K;  // 0x28 SmartMX with
        }
        // RATS?
        if (true) {
            return Type::MIFARE_Classic_1K;  // 0x08
        }
        // PlusEV1, PlusS, PlusX, PlusSE 1K (SL1)
        return Type::Unknown;
    }

    // Bit 4 No
    if (sak & 0x10 /*b5*/) {
        // Bit 5 Yes
        return (sak & 0x01) ? Type::MIFARE_Plus_4K /* 0x11*/ : Type::MIFARE_Plus_2K /* 0x10*/;
    }
    // Bit 5 No
    if (sak & 0x01 /*b1*/) {
        // TagNPlay
        return Type::Unknown;
    }
    // Bit 1 No
    if (sak & 0x20 /*b6*/) {
        return Type::ISO_14443_4;
    }
    // Bit 6 No
    uint8_t ver[16]{};
    if (!ntag_get_version(ver)) {
        // UltraLight or UltraLightC or NTAG203
        uint16_t discard{};
#if 0
        // Re-activate if get_version has been failed (PICC goes into IDLE mode)
        req_wup_device(discard, true /* REQA*/);
        if (!nfcaSelect(uid)) {
            M5_LIB_LOGE("Faild to re-select %s", uid.uidAsString().c_str());
            return Type::Unknown;
        }
#endif
        uint8_t des[] = {m5::stl::to_underlying(Command::AUTHENTICATE_1), 0x00};
        uint8_t rbuf[16]{};
        uint16_t rx_len = sizeof(rbuf);
        if (nfca_transceive(rbuf, rx_len, des, sizeof(des), TIMEOUT_3DES)) {
            if (rbuf[0] == 0xAF) {
                return Type::MIFARE_UltraLightC;
            }
        }
#if 1
        // Re-activate if transceive has been failed (PICC goes into IDLE mode)
        nfcaRequest(discard);
        return nfcaSelect(uid) ? Type::MIFARE_UltraLight : Type::Unknown;
#else
        // TODO : NTAG203
        return Type::MIFARE_UltraLight;
#endif
    }

    if (ver[0] != 0x00 || ver[1] != 0x04 /*NXP*/ || ver[7] != 0x03 /* ISO14443-A*/) {
        return Type::Unknown;
    }
    if (ver[2] == 0x04 /* NXP */) {
        // ver[6] Storage size code
        return (ver[6] == 0x0E)   ? Type::NTAG_212
               : (ver[6] == 0x0F) ? Type::NTAG_213
               : (ver[6] == 0x11) ? Type::NTAG_215
               : (ver[6] == 0x13) ? Type::NTAG_216
               : (ver[6] == 0x0B) ? ((ver[4] == 0x02) ? Type::NTAG_210u : Type::NTAG_210)
                                  : Type::Unknown;
    }
    if (ver[2] == 0x03 /*UltraLight */) {
        // UltraLight EV1, Nano
        return Type::Unknown;
    }

    return Type::Unknown;
}

bool UnitST25R3916::nfca_request_wakeup(uint16_t& atqa, const bool request)
{
    _encrypted = false;
    atqa       = 0;

    // REQA or WUPA
    if (!write_noresponse_timeout(TIMEOUT_REQ_WUP) ||  //
        !writeSettingsISO14443A(antcl) || !writeAuxiliaryDefinition(no_crc_rx) ||
        //        writeMaskMainInterrupt(mask) && writeMaskTimerAndNFCInterrupt(~I_nre) &&//
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||
        !writeDirectCommand(request ? CMD_TRANSMIT_REQA : CMD_TRANSMIT_WUPA)) {
        M5_LIB_LOGE("Failed to %s", request ? "REQA" : "WUPA");
        return false;
    }

    auto irq = wait_for_interrupt(I_rxe32 | I_col32, TIMEOUT_REQ_WUP);
    // M5_LIB_LOGE("IRQ:%08X", irq);

    if (is_irq32_rxe(irq)) {
        // ATQA
        uint8_t rbuf[2]{};
        uint16_t actual{};
        if (readFIFO(actual, rbuf, sizeof(rbuf)) && actual) {
            if (actual == 2) {
                atqa = ((uint16_t)rbuf[1] << 8) | (uint16_t)rbuf[0];
                M5_LIB_LOGD("ATQA:%04X", atqa);
            }
            // When ocuur collisions, the ATQA value is inaccurate
            return true;
        }
    }
    return is_irq32_collision(irq);
}

bool UnitST25R3916::nfca_anti_collision(uint8_t rbuf[5], const uint8_t lv)
{
    if (!rbuf || lv < 1 || lv > 3) {
        return false;
    }

    // ANTICOLL/SEL
    if (!write_noresponse_timeout(TIMEOUT_ANTICOLL) ||  //
        !writeSettingsISO14443A(antcl) || !writeAuxiliaryDefinition(0)
        //        !writeMaskMainInterrupt(~(I_rxe | I_col)) || !writeMaskTimerAndNFCInterrupt(~(I_nre | I_cac))) {
    ) {
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
            M5_LIB_LOGD("Failed ANTICOL:%02X %08X", lv, irq);
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

bool UnitST25R3916::nfcaSelect(const UID& uid)
{
    _encrypted = false;
    if (!(uid.size == 4 || uid.size == 7 || uid.size == 10)) {
        return false;
    }

    bool completed{};
    uint8_t select_frame[7] = {0x93, 0x70};
    uint8_t rbuf[3]{};
    uint8_t lv{1};
    uint8_t offset{};

    if (!writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0)) {
        M5_LIB_LOGE("Failed to settings");
        return false;
    }

    do {
        select_frame[0] = 0x91 + lv * 2;
        // Build frame
        if (uid.size > lv * 3 + 1) {
            select_frame[2] = 0x88;
        } else {
            select_frame[2] = uid.uid[offset++];
        }
        select_frame[3] = uid.uid[offset++];
        select_frame[4] = uid.uid[offset++];
        select_frame[5] = uid.uid[offset++];
        select_frame[6] = calculate_bcc8(select_frame + 2, 4);

        // Select
        uint16_t rx_len{3};
        if (!nfca_transceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
            M5_LIB_LOGE("Failed to select");
            return false;
        }
        completed = is_sak_completed(rbuf[0]);

        ++lv;
    } while (!completed && lv < 4);
    return completed;
}

bool UnitST25R3916::nfcaSelectWithAnticollision(bool& completed, UID& uid, const uint8_t lv)
{
    completed  = false;
    _encrypted = false;

    // Resolve collision
    // M5_LIB_LOGE(">>> ANTICOLL");
    uint8_t rbuf[5]{};
    if (!nfca_anti_collision(rbuf, lv)) {
        return false;
    }
    // M5_LIB_LOGE("<<< ANTICOLL");

    // Copy UID
    memcpy(uid.uid + (lv - 1) * 3, rbuf + (rbuf[0] == 0x88), 4 - (rbuf[0] == 0x88));

    uint8_t select_frame[7] = {(uint8_t)(0x91 + lv * 2), 0x70};
    memcpy(select_frame + 2, rbuf, sizeof(rbuf));

    // Select
    uint16_t rx_len{3};
    if (  //! writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) ||
        !nfca_transceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
        M5_LIB_LOGE("Failed to select");
        return false;
    }

    uint8_t sak = rbuf[0];
    // M5_LIB_LOGE(">>>> SAK:%02X (%u)", sak, is_sak_completed(sak));
    //   Completed?
    if (is_sak_completed(sak)) {
        uid.size = 4 + (lv - 1) * 3;
        uid.sak  = sak;
        // uid.type   = get_type(uid.sak);
        // uid.blocks = get_number_of_blocks(uid.type);
        completed = true;
    }
    return is_sak_completed(sak) || has_sak_dependent_bit(sak);  // completed or continue
}

bool UnitST25R3916::nfcaHlt()
{
    const uint8_t hlt_frame[2] = {m5::stl::to_underlying(Command::HLTA), 0x00};

#if 0

    if (!write_noresponse_timeout(TIMEOUT_HALT) || !writeSettingsISO14443A(0x00 /*standard*/) ||
        !writeAuxiliaryDefinition(0) ||
        //! writeMaskMainInterrupt(~I_txe) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(hlta, sizeof(hlta)) ||
        !writeNumberOfTransmittedBytes(sizeof(hlta), 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
#else
    if (_encrypted) {
        if (!write_noresponse_timeout(TIMEOUT_HALT) || !mifare_classic_send_encrypt(hlt_frame, sizeof(hlt_frame))) {
            return false;
        }
    } else {
        if (!write_noresponse_timeout(TIMEOUT_HALT) ||                                                           //
            !writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) ||                        //
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
            !writeFIFO(hlt_frame, sizeof(hlt_frame)) || !writeNumberOfTransmittedBytes(sizeof(hlt_frame), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
            return false;
        }
    }
#endif
    _encrypted = false;
    // No response is coming back, so need to confirm if it was sent
    auto irq = wait_for_interrupt(I_txe32, TIMEOUT_HALT);
    return is_irq32_txe(irq);
}

bool UnitST25R3916::nfcaReadBlock(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    uint8_t cmd[2] = {m5::stl::to_underlying(Command::READ), addr};
    if (  //! writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
        !nfca_transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ)) {
        M5_LIB_LOGE("Failed to transcive");
        return false;
    }
    return true;
}

// -------------------------------- For Mifare classic
bool UnitST25R3916::mifare_classic_send_encrypt(const uint8_t* tx, const uint16_t tx_len)
{
    if (!tx || !tx_len || tx_len > 32) {
        return false;
    }

    // Send
    uint8_t tmp_tx[tx_len + 2 /*CRC*/]{};
    memcpy(tmp_tx, tx, tx_len);

    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    auto crc           = crc16.range(tx, tx_len);
    tmp_tx[tx_len]     = crc & 0xFF;
    tmp_tx[tx_len + 1] = crc >> 8;

    uint8_t enc_tx[tx_len + 2]{};
    uint32_t parity = _crypto1.encrypt(enc_tx, tmp_tx, sizeof(tmp_tx));

    uint8_t bitstream[tx_len + 2 + ((tx_len + 7) >> 3)]{};
    append_parity(bitstream, sizeof(bitstream), enc_tx, sizeof(enc_tx), parity);

    uint8_t sbytes = tx_len + 2;
    uint8_t sbits  = ((tx_len + 2) << 3) >> 3;

    /*
    M5_LIB_LOGE(">>>>> send:%u/%u", sbytes, sbits);
    m5::utility::log::dump(tx, tx_len, false);
    m5::utility::log::dump(tmp_tx, sizeof(tmp_tx), false);
    m5::utility::log::dump(enc_tx, sizeof(enc_tx), false);
    m5::utility::log::dump(bitstream, sizeof(bitstream), false);
    */

    if (!writeSettingsISO14443A(no_tx_par) ||  //! writeAuxiliaryDefinition(no_crc_rx) ||                 //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                  //
        !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sbytes, sbits) ||  //
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGE("Failed to send");
        return false;
    }
    return true;
}

bool UnitST25R3916::mifare_classic_transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx,
                                                      const uint16_t tx_len, const uint32_t timeout_ms,
                                                      const bool include_crc, const bool decrypt)
{
    if (!rx || !rx_len || !tx || !tx_len || tx_len > 32) {
        return false;
    }

    // Send
    if (!writeAuxiliaryDefinition(include_crc ? no_crc_rx : 0) || !mifare_classic_send_encrypt(tx, tx_len)) {
        M5_LIB_LOGE("SNED ERROR");
        return false;
    }

    // Read
    const uint32_t rlen = rx_len + (include_crc ? 2 : 0 /* CRC */);

    if (!wait_for_FIFO(timeout_ms, rlen)) {
        M5_LIB_LOGE("Timeout");
        return false;
    }

    uint8_t rbuf[rlen]{};
    uint16_t actual{};
    if (!readFIFO(actual, rbuf, sizeof(rbuf)) || actual != rlen) {
        M5_LIB_LOGE("Failed to readFIFO %u", actual);
        return false;
    }

    // M5_LIB_LOGE("read: %u/%u", actual, rlen);

    // Decryption
    if (decrypt) {
        for (uint_fast8_t i = 0; i < rlen; ++i) {
            rbuf[i] ^= _crypto1.step8(0);
        }
    }

    // m5::utility::log::dump(dec_rx, actual, false);

    if (include_crc) {
        m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
        uint16_t crc = crc16.range(rbuf, rx_len);
        if ((crc & 0xFF) != rbuf[rlen - 2] || ((crc >> 8) != rbuf[rlen - 1])) {
            M5_LIB_LOGE("CRC ERROR: C:%04x R:%02x%02x", crc, rbuf[rlen - 2], rbuf[rlen - 1]);
            return false;
        }
    }
    actual = std::min<uint16_t>(actual - (include_crc ? 2 : 0), rx_len);
    memcpy(rx, rbuf, actual);

    // M5_LIB_LOGE("copy: %u/%u", actual, rx_len);

    return true;
}

bool UnitST25R3916::mifareClassicReadBlock(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    uint8_t cmd[2] = {m5::stl::to_underlying(Command::READ), addr};
    return mifare_classic_transceive_encrypt(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ, true, true);
}

bool UnitST25R3916::mifare_classic_authenticate(const Command cmd, const UID& uid, const uint8_t block, const Key& mkey)
{
    if ((cmd != Command::AUTH_WITH_KEY_A && cmd != Command::AUTH_WITH_KEY_B) || !uid.isClassic()) {
        return false;
    }

    // 3-pass mutual authentication
    const uint64_t key48 = key_to64(mkey.data());

    // 1) Send AUTH command and receive token RB (Nt)
    uint8_t auth_frame[2] = {m5::stl::to_underlying(cmd), block};
    uint8_t RB[4]{};
    uint16_t rlen{4};

    if (_encrypted) {
        if (!mifare_classic_transceive_encrypt(RB, rlen, auth_frame, sizeof(auth_frame), TIMEOUT_AUTH1, false, false)) {
            M5_LIB_LOGE("Failed to send AUTH1(encrypt) %u", rlen);
            return false;
        }
    } else {
        if (  //! writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
            !nfca_transceive(RB, rlen, auth_frame, sizeof(auth_frame), TIMEOUT_AUTH1)) {
            M5_LIB_LOGE("Failed to send AUTH1(plain) %u", rlen);
            return false;
        }
    }
    m5::utility::delayMicroseconds(87);  // Wait for AUTH <-> Sebd AB (At least 86.4 us)

    // 2) Send encrypt token AB (Nr, Ar)
    uint8_t tail4[4]{};
    uid.tail4(tail4);
    const uint32_t u32 = array_to32(tail4);
    uint32_t Nt        = array_to32(RB);
    const uint32_t Nr  = esp_random();  // Change another RNG engine if you want
    uint32_t Ar{}, suc3{};
    uint8_t AB[8]{};
    uint8_t parity{};
    uint8_t bitstream[9 /* AB 8bytes + encrypt parity 1(8bits)] */]{};

    // M5_LIB_LOGE("Nt:%08X", Nt);

    _crypto1.init(key48);
    if (!_encrypted) {
        (void)_crypto1.inject(u32, Nt, false);
    } else {
        Nt = _crypto1.inject(u32, Nt, true) ^ Nt;
    }
    suc_23(m5::stl::byteswap(Nt), Ar /* == suc2 */, suc3);

    M5_LIB_LOGD("Auth:%u  mkey:%llX uid:%X Nt:%X Nr:%X Ar:%X suc3:%X", block, key48, u32, Nt, Nr, Ar, suc3);

    parity = _crypto1.encrypt(AB, Nr, Ar);
    append_parity(bitstream, sizeof(bitstream), AB, sizeof(AB), parity);

    writeDirectCommand(CMD_RESET_RX_GAIN);

    if (!write_noresponse_timeout(TIMEOUT_AUTH2) ||                                                          //
        !writeSettingsISO14443A(no_tx_par) || !writeAuxiliaryDefinition(no_crc_rx) ||                        //
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
        !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGE("Failed to AUTH2(encrypt)");
        return false;
    }
    if (!wait_for_FIFO(TIMEOUT_AUTH2, 4)) {
        M5_LIB_LOGE("Timeout AUTH2");
        return false;
    }

    // 3) Receive token BA (At)
    uint8_t BA[4]{};
    uint16_t actual{};
    if (!readFIFO(actual, BA, sizeof(BA)) || actual != 4) {
        M5_LIB_LOGE("Failed to readFIFO AUTH2 %u", actual);
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

// -------------------------------- For NTAG
bool UnitST25R3916::ntag_fast_read(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    uint8_t cmd[3] = {m5::stl::to_underlying(Command::FAST_READ), spage, epage};
    if (  //! writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
        !nfca_transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ)) {
        M5_LIB_LOGE("Failed to transcive");
        return false;
    }
    return true;
}

bool UnitST25R3916::ntag_get_version(uint8_t info[10])
{
    uint8_t gv[1]   = {m5::stl::to_underlying(Command::GET_VERSION)};
    uint16_t rx_len = 10;
    return nfca_transceive(info, rx_len, gv, sizeof(gv), TIMEOUT_GET_VERSION);
}

}  // namespace unit
}  // namespace m5
