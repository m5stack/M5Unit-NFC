/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916.cpp
  @brief ST25R3916 Unit for M5UnitUnified
*/
#include <Arduino.h>
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;
using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
// HackerCap <-> CardputerADV pin configurations (EXT 2.54-14P)
constexpr int PIN_SCK{40};           // G40
constexpr int PIN_MOSI{14};          // G14
constexpr int PIN_MISO{39};          // G39
constexpr int PIN_CS_ST25R3916{6};   // G6  -> ST25R3916 CS
constexpr int PIN_ST25R3916_IRQ{4};  // G4  -> ST25R3916 IRQ
constexpr int PIN_CS_CC1101{5};      // G5  -> CC1101 CS
constexpr int PIN_POWER_EN{3};       // G3  -> POWER_EN

#define TRANSACTION_GUARD() transaction_guard _tg_(adapter())

constexpr uint8_t VALID_IDENTIFY_TYPE{0x05};  // 00000101b (ST25R3916/7)
constexpr uint16_t MAX_FIFO_DEPTH{512};       // Maximum FIFO depth

constexpr uint16_t PREFIX_SPACE_B{(uint16_t)CMD_REGISTER_SPACEB_ACCESS << 8};

// Operation modes
constexpr uint8_t OP_TRAILER_MASK{0x3F};             // 00111111b
constexpr uint8_t OP_WRITE_REGISTER{0x00};           // 00xxxxxxb
constexpr uint8_t OP_READ_REGISTER{0x40};            // 01xxxxxxb
constexpr uint8_t OP_LOAD_FIFO{0x80};                // 10000000b
constexpr uint8_t OP_LOAD_PT_MEMORY_A_CONFIG{0xA0};  // 10100000b
constexpr uint8_t OP_LOAD_PT_MEMORY_F_CONFIG{0xA8};  // 10101000b
constexpr uint8_t OP_LOAD_PT_MEMORY_TSN_DATA{0xAC};  // 10101100b
constexpr uint8_t OP_LOAD_PT_MEMORY{0xBF};           // 10111111b
constexpr uint8_t OP_READ_FIFO{0x9F};                // 10011111b
constexpr uint8_t OP_DIRECT_COMMAND{0xC0};           // 11xxxxxxb;

//
constexpr uint32_t TIMEOUT_REQ_WUP{4};
constexpr uint32_t TIMEOUT_SELECT{4};
constexpr uint32_t TIMEOUT_HALT{2};
constexpr uint32_t TIMEOUT_GET_VERSION{5};
constexpr uint32_t TIMEOUT_3DES{10};
constexpr uint32_t TIMEOUT_AUTH1{5};
constexpr uint32_t TIMEOUT_AUTH2{500};
constexpr uint32_t TIMEOUT_READ{10};
constexpr uint32_t TIMEOUT_WRITE1{5};
constexpr uint32_t TIMEOUT_WRITE2{10};
constexpr uint32_t TIMEOUT_OP{5};  // Inc/Dec/Restore...

//
constexpr uint32_t I_wl32  = ((uint32_t)I_wl << 24);
constexpr uint32_t I_rxs32 = ((uint32_t)I_rxs << 24);
constexpr uint32_t I_rxe32 = ((uint32_t)I_rxe << 24);
constexpr uint32_t I_txe32 = ((uint32_t)I_txe << 24);
constexpr uint32_t I_col32 = ((uint32_t)I_col << 24) | ((uint32_t)I_cac << 16);
constexpr uint32_t I_nre32 = ((uint32_t)I_nre << 16);

/*
  To prevent the internal overheat protection to trigger below the junction temperature,
  the 3-byte frame FCh / 04h / 10h (register access / address / value) has to be sent after power-on and Set default
  command.
*/
constexpr uint8_t protection_command[] = {0x04, 0x10};

inline uint8_t to_read_reg(const uint8_t regA)
{
    return (regA & OP_TRAILER_MASK) | OP_READ_REGISTER;
}

inline uint16_t to_read_reg(const uint16_t regB)
{
    return (regB & OP_TRAILER_MASK) | PREFIX_SPACE_B | OP_READ_REGISTER;
}

inline uint8_t to_write_reg(const uint8_t regA)
{
    return (regA & OP_TRAILER_MASK) | OP_WRITE_REGISTER;
}

inline uint16_t to_write_reg(const uint16_t regB)
{
    return (regB & OP_TRAILER_MASK) | PREFIX_SPACE_B | OP_WRITE_REGISTER;
}

constexpr uint16_t io_config12_i2c{io_drv_lvl};
constexpr uint16_t io_config12_spi{miso_pd1 | miso_pd2};

float regulated_voltages(const uint8_t regulator_display_reg_value, const bool voltage5V = false)
{
    auto rv = (regulator_display_reg_value >> 4) & 0x0F;
    if (voltage5V) {
        return 3.6f + 0.1f * rv;
    }
    return (rv < 5) ? std::numeric_limits<float>::quiet_NaN() : 2.4f + (0.1f * (rv - 5));
}

uint16_t calculate_nrt(const uint32_t ms, const bool fc4096)
{
    auto step_sec = (fc4096 ? 4096 : 64) / 13560000.f;
    uint32_t nrt  = (uint32_t)std::round((ms / 1000.f) / step_sec);
    uint32_t max  = fc4096 ? 0xFFFF : 0xF857;
    if (nrt > max) {
        nrt = max;
    }
    // M5_LIB_LOGE(">>>> %ums %u => %04X", ms, fc4096, nrt);
    return nrt;
}

// constexpr uint32_t timeout{4};
// constexpr uint32_t timeout{200};

inline bool is_irq32_error(const uint32_t irq32)
{
    return irq32 & 0x0000FF00;
}

inline bool is_irq32_timeout(const uint32_t irq32)
{
    return irq32 & I_nre32;
}

inline bool is_irq32_received(const uint32_t irq32)
{
    return irq32 & I_rxe32;
}

inline bool is_irq32_collision(const uint32_t irq32)
{
    return irq32 & I_col32;
}

uint32_t suc_k(const uint32_t Nt, const uint32_t k)
{
    m5::utility::FibonacciLFSR_Right<16, 16, 14, 13, 11> tmp(Nt);
    for (uint32_t i = 0; i < k; ++i) {
        tmp.next32();
    }
    return tmp.next32();
}

void suc_23(const uint32_t Nt, uint32_t& suc2, uint32_t& suc3)
{
    m5::utility::FibonacciLFSR_Right<16, 16, 14, 13, 11> tmp(Nt);
    tmp.next32();
    tmp.next32();
    suc2 = tmp.next32();
    suc3 = tmp.next32();
}

uint32_t swap_endian_32(const uint32_t value)
{
    return ((value >> 24) & 0x000000FF) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
}

uint16_t swap_endian_16(const uint16_t value)
{
    return (value >> 8) | (value << 8);
}

uint8_t swap_bit_order(const uint8_t byte)
{
    return (byte * 0x0202020202ULL & 0x010884422010ULL) % 0x3ff;
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

void dump_block(const uint8_t* buf, const int16_t block = -1, const int16_t sector = -1, const uint8_t ab = 0xFF,
                const bool aberror = false, const bool valueblock = false)
{
    char tmp[128 + 1] = "   ";
    uint32_t left{};
    // Sector
    if (sector >= 0) {
        left = snprintf(tmp, 4, "%02d)", sector);
    } else {
        left = 3;
    }
    // Block
    if (block >= 0) {
        left += snprintf(tmp + left, 7, "[%03d]:", block);
    } else {
        strcat(tmp, "      ");
        left += 6;
    }
    // Data
    for (uint8_t i = 0; i < 16; ++i) {
        left += snprintf(tmp + left, 4, "%02X ", buf[i]);
    }
    // Access bits
    if (ab != 0xFF) {
        if (!aberror) {
            left += snprintf(tmp + left, 8, "[%d %d %d]", (ab >> 2) & 1, (ab >> 1) & 1, (ab & 1));
        } else {
            strcat(tmp + left, "[ERROR]");
            left += 7;
        }
    }
    if (valueblock) {
        int32_t value{};
        uint8_t addr{};
        if (decode_value_block(value, addr, buf)) {
            snprintf(tmp + left, 26, " Addr:%03u Val:%" PRId32 "", addr, value);  // PRId32 for compile on NanoC6
        } else {
            strcat(tmp + left, "[Illgal value blcok]");
        }
    }
    ::puts(tmp);
}

}  // namespace

namespace m5 {
namespace unit {

// --------------------------------
// class UnitST25R3916
const char UnitST25R3916::name[] = "UnitST25R3916";
const types::uid_t UnitST25R3916::uid{"UnitST25R39162"_mmh3};
const types::attr_t UnitST25R3916::attr{attribute::AccessI2C | attribute::AccessSPI};

void IRAM_ATTR UnitST25R3916::on_irq(void* arg)
{
    UnitST25R3916* u       = static_cast<UnitST25R3916*>(arg);
    u->_interrupt_occurred = true;
}

bool UnitST25R3916::begin()
{
    // Chip detection
    uint8_t type{}, rev{};
    if (!readICIdentity(type, rev) || type != VALID_IDENTIFY_TYPE || rev == 0) {
        M5_LIB_LOGE("Not detected ST25R3916 %02X,%02X", type, rev);
        return false;
    }

    // Power-on sequence
    // 1) Set to default
    if (!writeDirectCommand(CMD_SET_DEFAULT)) {
        M5_LIB_LOGE("Failed to CMD_SET_DEFAULT");
        return false;
    }
    // 2) To prevent the internal overheat protection to trigger below the junction temperature
    if (!writeDirectCommand(CMD_TEST_ACCESS, protection_command, sizeof(protection_command))) {
        M5_LIB_LOGE("Failed to send protection command");
        return false;
    }
    // 3) I/O settings
    if (!writeIOConfiguration((adapter()->type() == Adapter::Type::I2C ? io_config12_i2c : io_config12_spi) |
                              (_cfg.vdd_voltage_5V ? 0x0000 : sup3v))) {
        M5_LIB_LOGE("Failed to writeIOConfiguration");
        return false;
    }

    // 4) The internal voltage regulators have to be configuration
    // It is recommended to use direct command Adjust regulators to improve the system PSRR.
    if (!writeMaskInterrupts(0xFFFF00FF) && clearInterrupts()) {  // Mask all interrupts exclusive error
        M5_LIB_LOGE("Failed to writeMaskInterrupt");
        return false;
    }

    // Adjust regulators
    if (!writeOperationControl(en)) {
        M5_LIB_LOGE("Failed to writeOperationControl");
        return false;
    }
    if (!writeDirectCommand(CMD_ADJUST_REGULATORS)) {
        M5_LIB_LOGE("Failed to CMD_ADJUST_REGULATORS");
        return false;
    }
    m5::utility::delay(5);  // Need wait

    // Check vdd voltage
    uint8_t value{};
    if (readRegulatorDisplay(value)) {
        M5_LIB_LOGD("Regulated voltages:%02X:%1.1fV", value, regulated_voltages(value, _cfg.vdd_voltage_5V));
    }

    // Antenna Settings
    uint8_t txd{};
    if (!readTXDriver(txd) || !writeTXDriver((txd & 0x0F) | ((_cfg.tx_am_modulation & 0x0F) << 4))) {
        M5_LIB_LOGE("Failed to TXDriver");
        return false;
    }
    readTXDriver(txd);
    M5_LIB_LOGD("TXD:%02X", txd);

    writeReceiverConfiguration1(0x08);  // z600k
    writeReceiverConfiguration2(0x2D);  // sqm_dyn , agc_en, agc_m, agc6_3,
    writeReceiverConfiguration3(0x00);
    writeReceiverConfiguration4(0x00);

    ////////
    // ISO14443A
    // M5_LIB_LOGE(">>>>>> try ISO14443A REQA");
    writeInitiatorOperationMode(InitiatorOperationMode::ISO14443A, 0x01 /* nfc_ar01 */);
    writeBitrate(Bitrate::FC128_106Kbits, Bitrate::FC128_106Kbits);
    writeSettingsISO14443A(0x0);

    //
    writeOperationControl(en | rx_en | tx_en);
    writeMaskInterrupts(0);
    writeDirectCommand(CMD_NFC_INITIAL_FIELD_ON);
    m5::utility::delay(5);

    return true;
}

bool UnitST25R3916::req_wup_device(uint16_t& atqa, const bool req)
{
    atqa = 0;
    //    constexpr uint8_t mask = ~(I_rxe | I_col);
    //    constexpr uint32_t wait{I_rxe32 | I_col32};

    // REQA or WUPA
    if (!write_noresponse_timeout(TIMEOUT_REQ_WUP) || !writeSettingsISO14443A(antcl) || !writeAuxiliaryDefinition(0) ||
        //        writeMaskMainInterrupt(mask) && writeMaskTimerAndNFCInterrupt(~I_nre) &&//
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||
        !writeDirectCommand(req ? CMD_TRANSMIT_REQA : CMD_TRANSMIT_WUPA)) {
        M5_LIB_LOGE("Failed to %s", req ? "REQA" : "WUPA");
        return false;
    }
    /*
    auto irq = wait_for_interrupt(wait, TIMEOUT_REQ_WUP);
    if (is_irq32_error(irq) || !(irq & wait)) {
    }
}
    */
    if (!wait_for_FIFO(TIMEOUT_REQ_WUP)) {
        M5_LIB_LOGE("%s Timeout", req ? "REQA" : "WUPA");
        return false;
    }

    // ATQA
    uint8_t rbuf[2]{};
    uint16_t actual{};
    if (readFIFO(actual, rbuf, sizeof(rbuf)) && actual) {
        if (actual == 2) {
            atqa = ((uint16_t)rbuf[1] << 8) | (uint16_t)rbuf[0];
            // M5_LIB_LOGE(">>>>ATQA:%04X", atqa);
        }
        // When ocuur collisions, the ATQA value is inaccurate
        return true;
    }
    return false;
}

// #define DBG_ANTICOLL

bool UnitST25R3916::anti_collision(uint8_t rbuf[5], const uint8_t lv)
{
    if (!rbuf || lv < 1 || lv > 3) {
        return false;
    }

    // ANTICOLL/SEL
#if defined(DBG_ANTICOLL)
    M5_LIB_LOGE("======================== ANTICOL%u", lv);
#endif
    if (!write_noresponse_timeout(TIMEOUT_SELECT) || !writeSettingsISO14443A(antcl) || !writeAuxiliaryDefinition(0)
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

        auto irq  = wait_for_interrupt(I_rxe32 | I_col32, TIMEOUT_SELECT);
        collision = is_irq32_collision(irq);
#if defined(DBG_ANTICOLL)
        M5_LIB_LOGE("===> ANTICOLL IRQ:%08X col:%u", irq, collision);
#endif
        if (!collision && !is_irq32_received(irq)) {
            M5_LIB_LOGE("Failed ANTICOL:%02X %08X", lv, irq);
            return false;
        }

        uint8_t cd{};
        if (!readFIFO(actual, rbuf + rbuf_offset, 5 - rbuf_offset) || !actual || !readCollisionDisplay(cd)) {
            return false;
        }
#if defined(DBG_ANTICOLL)
        M5_LIB_LOGE(" >>>> acrual: %u roff: %u", actual, rbuf_offset);
        m5::utility::log::dump(rbuf, 5, false);
#endif

        // OCCUR collision
        if (collision) {
            // M5_LIB_LOGE(">>>>>>>>>>>>>>>>> OCCUR COLLISION >>>>>>>>>>>>>>>>>>>>>>");
            uint8_t cbytes = ((cd >> 4) & 0x0F);  // c_byte[3:0]
            uint8_t cbits  = ((cd >> 1) & 0x07);  // c_bit[2:0]
            if (actual) {
                coll_byte = rbuf[rbuf_offset + actual - 1];  // from LSB
                coll_byte |= 1U << cbits;
            }
#if defined(DBG_ANTICOLL)
            M5_LIB_LOGE("   COL:%u bytes, %u bits", cbytes, cbits);
            M5_LIB_LOGE(">>>>> coll byte: %02x", coll_byte);
#endif
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

bool UnitST25R3916::select(const UID& uid)
{
    if (!(uid.size == 4 || uid.size == 7 || uid.size == 10)) {
        return false;
    }

    bool completed{};
    uint8_t select_frame[7] = {0x93, 0x70};
    uint8_t rbuf[3]{};
    uint8_t lv{1};
    uint8_t offset{};

    if (!write_noresponse_timeout(TIMEOUT_SELECT)) {
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
        if (!writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) || !clearInterrupts() ||
            !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(select_frame, sizeof(select_frame)) ||
            !writeNumberOfTransmittedBytes(sizeof(select_frame), 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
            return false;
        }
        auto irq = wait_for_interrupt(I_rxe32, TIMEOUT_SELECT);
        if (!is_irq32_received(irq)) {
            M5_LIB_LOGE("Failed SEL %08X", irq);
            return false;
        }
        uint16_t actual{};
        if (!readFIFO(actual, rbuf, sizeof(rbuf)) && actual) {
            return false;
        }
        // m5::utility::log::dump(rbuf, actual, false);
        completed = is_sak_completed(rbuf[0]);

        ++lv;
    } while (!completed && lv < 4);
    return completed;
}

bool UnitST25R3916::select_with_anticollision(bool& completed, UID& uid, const uint8_t lv)
{
    completed = false;

    // Resolve collision
    // M5_LIB_LOGE(">>> ANTICOLL");
    uint8_t rbuf[5]{};
    if (!anti_collision(rbuf, lv)) {
        return false;
    }
    // M5_LIB_LOGE("<<< ANTICOLL");

    // Copy UID
    memcpy(uid.uid + (lv - 1) * 3, rbuf + (rbuf[0] == 0x88), 4 - (rbuf[0] == 0x88));

    uint8_t select_frame[7] = {(uint8_t)(0x91 + lv * 2), 0x70};
    memcpy(select_frame + 2, rbuf, sizeof(rbuf));

    // Select
    if (!writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) || !clearInterrupts() ||
        !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(select_frame, sizeof(select_frame)) ||
        !writeNumberOfTransmittedBytes(sizeof(select_frame), 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
    auto irq = wait_for_interrupt(I_rxe32, TIMEOUT_SELECT);
    // M5_LIB_LOGE("===> SEL IRQ:%08X", irq);
    if (!is_irq32_received(irq)) {
        M5_LIB_LOGE("Failed SEL %08X", irq);
        return false;
    }

    uint16_t actual{};
    if (readFIFO(actual, rbuf, sizeof(rbuf)) && actual) {
        // m5::utility::log::dump(rbuf, actual, false);
        uint8_t sak = rbuf[0];
        // M5_LIB_LOGE(">>>> SAK:%02X (%u)", sak, is_sak_completed(sak));
        //   Completed?
        if (is_sak_completed(sak)) {
            uid.size   = 4 + (lv - 1) * 3;
            uid.sak    = sak;
            uid.type   = get_type(uid.sak);
            uid.blocks = get_number_of_blocks(uid.type);
            completed  = true;
        }
        return is_sak_completed(sak) || has_sak_dependent_bit(sak);  // completed or continue
    }
    return false;
}

bool UnitST25R3916::hltA()
{
    const uint8_t hlta[2] = {m5::stl::to_underlying(Command::HLTA), 0x00};
    if (!write_noresponse_timeout(TIMEOUT_HALT) || !writeSettingsISO14443A(0x00 /*standard*/) ||
        //! writeAuxiliaryDefinition(0) || !writeMaskMainInterrupt(~I_txe) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(hlta, sizeof(hlta)) ||
        !writeNumberOfTransmittedBytes(sizeof(hlta), 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
    auto irq = wait_for_interrupt(I_txe32, TIMEOUT_HALT);
    return irq & I_txe32;
}

bool UnitST25R3916::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                               const uint32_t timeout_ms)
{
    const auto rx_len_org = rx_len;
    rx_len                = 0;
    if (!rx || !rx_len_org || !tx || !tx_len) {
        M5_LIB_LOGE("Argument error %p/%u %p:%u", rx, rx_len_org, tx, tx_len);
        return false;
    }

    if ((timeout_ms ? !write_noresponse_timeout(timeout_ms) : false) ||
        //        !writeMaskMainInterrupt(~I_rxe) || !writeMaskTimerAndNFCInterrupt(~I_nre) ||//
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(tx, tx_len) ||
        !writeNumberOfTransmittedBytes(tx_len, 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }

#if 0
    auto irq = wait_for_interrupt(I_rxe32, timeout_ms);
    if (!is_irq32_received(irq)) {
        M5_LIB_LOGE("Failed to transceive %08X", irq);
        return false;
    }
#else
    if (!wait_for_FIFO(timeout_ms, rx_len_org)) {
        M5_LIB_LOGE("Timeout");
        // >>>>>>>>>
        if (tx) {
            m5::utility::log::dump(tx, tx_len, false);
        }
        return false;
    }
#endif

    uint16_t actual{};
    if (readFIFO(actual, rx, rx_len_org)) {
        rx_len = actual;
        return true;
    }
    M5_LIB_LOGE("Failed to readFIFO");
    return false;
}

bool UnitST25R3916::transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                       const uint32_t timeout_ms)
{
    if (!rx || !rx_len || !tx || !tx_len) {
        return false;
    }

    //    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    //    auto crc = crc16.range(tx, tx_len);

    uint16_t enc_tx_len{};
    uint8_t enc_tx[tx_len + (tx_len + 7) / 8]{};
    for (uint_fast16_t i = 0; i < tx_len; ++i) {
        uint8_t ks = _crypto1.step8(0);
        enc_tx[i]  = tx[i] ^ ks;
    }

    return false;
}

bool UnitST25R3916::read_block(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    // In encrypted
    uint8_t cmd[4] = {m5::stl::to_underlying(Command::READ), addr};
    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    auto crc = crc16.range(cmd, 2);
    cmd[2]   = crc & 0xFF;
    cmd[3]   = crc >> 8;

    auto oddparity8 = [](const uint8_t x) -> uint8_t { return !__builtin_parity(x); };

    uint8_t enc_tx[4]{};
    uint8_t parity{};
    for (uint8_t i = 0; i < 4; ++i) {
        uint8_t ks = _crypto1.step8(0);
        enc_tx[i]  = cmd[i] ^ ks;
        parity |= ((_crypto1.filter() ^ oddparity8(cmd[i])) & 1) << i;
    }

    uint8_t bitstream[5] = {0};
    uint32_t bitpos      = 0;
    auto put_bit         = [&](uint8_t b) {
        uint32_t byte = bitpos >> 3;
        uint8_t off   = bitpos & 7;
        if (b) bitstream[byte] |= (1u << off);
        bitpos++;
    };
    for (int i = 0; i < 4; ++i) {
        uint8_t v = enc_tx[i];
        for (int k = 0; k < 8; ++k) put_bit((v >> k) & 1u);  // LSB→MSB
        put_bit((parity >> i) & 1u);
    }

    // Send
    // M5_LIB_LOGE("Send: parity:%04X cnt:%u", parity, _crypto1._count);
    //    m5::utility::log::dump(cmd, 4, false);
    //    m5::utility::log::dump(enc_tx, 4, false);
    //    m5::utility::log::dump(bitstream, 5, false);

    if (!writeSettingsISO14443A(no_tx_par /*| no_rx_par*/) || !writeAuxiliaryDefinition(no_crc_rx /*| 0x04*/) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||  //
        !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(4, 4) ||
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGE("Failed to send");
        return false;
    }

    // Read
#if 0
    //    auto irq = wait_for_interrupt(I_rxs32 | I_rxe32 | I_nre32, TIMEOUT_READ);
    auto irq = wait_for_interrupt(I_rxs32 | I_rxe32, TIMEOUT_READ);
    // M5_LIB_LOGE("===> READ IRQ:%08X", irq);
    uint16_t bytes{};
    uint8_t bits{};
    auto timeout_at = m5::utility::millis() + TIMEOUT_READ;
    do {
        readFIFOSize(bytes, bits);
        if (bytes == 18) {
            break;
        }

    } while (m5::utility::millis() <= timeout_at);
#else
    if (!wait_for_FIFO(TIMEOUT_READ, 18)) {
        M5_LIB_LOGE("Timeout");
        return false;
    }
#endif

    uint8_t rbuf[18]{};
    uint16_t actual{};
    if (!readFIFO(actual, rbuf, sizeof(rbuf)) || actual != 18) {
        M5_LIB_LOGE("Failed to readFIFO %u", actual);
        return false;
    }
    //    m5::utility::log::dump(rbuf, actual, false);

    // Decryption
    uint8_t rx_dec[18]{};
    for (uint_fast8_t i = 0; i < 18; ++i) {
        uint8_t ks = _crypto1.step8(0);
        rx_dec[i]  = rbuf[i] ^ ks;
    }

    //    m5::utility::log::dump(rx_dec, actual, false);
    crc16.clear();
    crc = crc16.range(rx_dec, 16);
    if ((crc & 0xFF) != rx_dec[16] || ((crc >> 8) != rx_dec[17])) {
        M5_LIB_LOGE("CRC ERROR: C:%04x R:%02x%02x", crc, rx_dec[17], rx_dec[16]);
        return false;
    }
    actual = std::min<uint16_t>(16u, rx_len);
    memcpy(rx, rx_dec, actual);

    return true;
}

bool UnitST25R3916::ntag_fast_read(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    uint8_t cmd[3] = {0x3A, spage, epage};
    return transceive(rx, rx_len, cmd, sizeof(cmd));
}

bool UnitST25R3916::ntag_dump_all(const uint8_t maxPage)
{
    puts(
        "Page      :00 01 02 03\n"
        "----------------------");

    for (uint_fast8_t page = 0; page < maxPage; page += 4) {
        if (!ntag_dump_page(page)) {
            return false;
        }
    }
    return true;
}

bool UnitST25R3916::ntag_dump_page(const uint8_t page)
{
    uint8_t buf[16]{};
    uint16_t rx_len = sizeof(buf);
    uint8_t baddr   = page & ~0x03;

    // 16bytes(4 pages)
    if (read_block(buf, rx_len, baddr)) {
        for (int_fast8_t off = 0; off < 4; ++off) {
            auto idx = off << 2;
            printf("[%3dD/%02XH]:%02X %02X %02X %02X\n", baddr + off, baddr + off, buf[idx + 0], buf[idx + 1],
                   buf[idx + 2], buf[idx + 3]);
        }
        return true;
    }
    for (int_fast8_t off = 0; off < 4; ++off) {
        printf("[%3d/%02X] ERROR\n", baddr + off, baddr + off);
    }
    return false;
}

void UnitST25R3916::update(const bool /*force*/)
{
    if (_interrupt_occurred) {
        uint32_t v{};
        if (readInterrupts(v)) {
            _irq_flags |= v;
            _interrupt_occurred = false;
        }
    }
}

bool UnitST25R3916::writeDirectCommand(const uint8_t cmd, const uint8_t* data, uint32_t dlen)
{
    TRANSACTION_GUARD();
    return writeRegister(cmd, data, dlen, false);
}

bool UnitST25R3916::readInterrupts(uint32_t& value)
{
    // The error register is reset to zero when reading the main register, so it must be read separately
    value = 0;
    uint8_t error{};
    uint16_t main_nfc{};
    uint8_t passive{};
    if (readErrorAndWakeupInterrupt(error) && read_register16(REG_MAIN_INTERRUPT, main_nfc) &&
        readPassiveTargetInterrupt(passive)) {
        value = ((uint32_t)main_nfc << 16) | ((uint32_t)error << 8) | ((uint32_t)passive);
        return true;
    }
    return false;
}

bool UnitST25R3916::clearInterrupts()
{
    _irq_flags = 0;
    uint32_t discard{};
    return read_register32(st25r3916::command::REG_MAIN_INTERRUPT, discard);
}

bool UnitST25R3916::writeInitiatorOperationMode(const InitiatorOperationMode mode, const uint8_t optional)
{
    uint8_t value = m5::stl::to_underlying(mode);  // targ 0
    value |= (0x07 & optional);                    // tr_am, ntc_ar01 if available
    return writeModeDefinition(value);
}

bool UnitST25R3916::writeTargetOperationMode(const TargetOperationMode mode, const uint8_t optional)
{
    uint8_t value = m5::stl::to_underlying(mode) | 0x80 /* targ 1 */;
    value |= (0x07 & optional);  // tr_am, ntc_ar01 if available
    return writeModeDefinition(value);
}

bool UnitST25R3916::writeBitrate(const st25r3916::Bitrate tx, const st25r3916::Bitrate rx)
{
    uint8_t value = (m5::stl ::to_underlying(tx) << 4) | m5::stl::to_underlying(rx);
    return writeBitrateDefinition(value);
}

bool UnitST25R3916::readFIFOSize(uint16_t& bytes, uint8_t& bits)
{
    bytes = bits = 0;

    uint16_t s{};
    if (readFIFOStatus(s)) {
        bytes = (s >> 8) | ((s & 0x00C0) << 2);
        bits  = (s >> 1) & 0x0007;
        return true;
    }
    return false;
}

bool UnitST25R3916::readFIFO(uint16_t& actual, uint8_t* buf, const uint16_t buf_size)
{
    actual = 0;

    uint16_t bytes{};
    uint8_t bits{};
    if (readFIFOSize(bytes, bits)) {
        auto readSz = std::min<uint16_t>(bytes + (bits != 0), buf_size);
        if (!readSz) {
            return false;
        }
        TRANSACTION_GUARD();
        if (!readRegister(OP_READ_FIFO, buf, readSz, 0, false)) {
            return false;
        }
        actual = readSz;
        return true;
    }
    return false;
}

bool UnitST25R3916::writeFIFO(const uint8_t* buf, const uint16_t buf_size)
{
    TRANSACTION_GUARD();

    if (!buf || !buf_size) {
        return false;
    }
    if (buf_size > MAX_FIFO_DEPTH) {
        M5_LIB_LOGE("Max FIFO depth is %u (%u)", MAX_FIFO_DEPTH, buf_size);
        return false;
    }
    return writeRegister(OP_LOAD_FIFO, buf, buf_size, false);
}

bool UnitST25R3916::readICIdentity(uint8_t& type, uint8_t& rev)
{
    type = rev = 0;
    uint8_t value{};
    if (read_register8(REG_IC_IDENTITY, value)) {
        type = (value >> 3) & 0x1F;
        rev  = value & 0x07;
        return true;
    }
    return false;
}

//
bool UnitST25R3916::read_register8(const uint8_t reg, uint8_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister8(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::read_register8(const uint16_t reg, uint8_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister8(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::write_register8(const uint8_t reg, const uint8_t v)
{
    TRANSACTION_GUARD();
    return writeRegister8(to_write_reg(reg), v, false);
}

bool UnitST25R3916::write_register8(const uint16_t reg, const uint8_t v)
{
    TRANSACTION_GUARD();
    return writeRegister8(to_write_reg(reg), v, false);
}

bool UnitST25R3916::set_bit_register8(const uint8_t reg, const uint8_t bits)
{
    TRANSACTION_GUARD();

    uint8_t v{};
    if (read_register8(reg, v)) {
        if ((v & bits) == bits) {
            return true;  // Already set spesific bits
        }
        return write_register8(reg, v | bits);
    }
    return false;
}

bool UnitST25R3916::set_bit_register8(const uint16_t reg, const uint8_t bits)
{
    TRANSACTION_GUARD();

    uint8_t v{};
    if (read_register8(reg, v)) {
        if ((v & bits) == bits) {
            return true;  // Already set spesific bits
        }
        return write_register8(reg, v | bits);
    }
    return false;
}

bool UnitST25R3916::clear_bit_register8(const uint8_t reg, const uint8_t bits)
{
    TRANSACTION_GUARD();

    uint8_t v{};
    if (read_register8(reg, v)) {
        if ((v & ~bits) == ~bits) {
            return true;  // Already cleared spesific bits
        }
        return write_register8(reg, v & ~bits);
    }
    return false;
}

bool UnitST25R3916::clear_bit_register8(const uint16_t reg, const uint8_t bits)
{
    TRANSACTION_GUARD();

    uint8_t v{};
    if (read_register8(reg, v)) {
        if ((v & ~bits) == ~bits) {
            return true;  // Already cleared spesific bits
        }
        return write_register8(reg, v & ~bits);
    }
    return false;
}

bool UnitST25R3916::read_register16(const uint8_t reg, uint16_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister16BE(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::read_register16(const uint16_t reg, uint16_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister16BE(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::write_register16(const uint8_t reg, const uint16_t v)
{
    TRANSACTION_GUARD();
    return writeRegister16BE(to_write_reg(reg), v, false);
}

bool UnitST25R3916::write_register16(const uint16_t reg, const uint16_t v)
{
    TRANSACTION_GUARD();
    return writeRegister16BE(to_write_reg(reg), v, false);
}

bool UnitST25R3916::read_register32(const uint8_t reg, uint32_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister32BE(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::read_register32(const uint16_t reg, uint32_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister32BE(to_read_reg(reg), v, 0, false);
}

bool UnitST25R3916::write_register32(const uint8_t reg, const uint32_t v)
{
    TRANSACTION_GUARD();
    return writeRegister32BE(to_write_reg(reg), v, false);
}

bool UnitST25R3916::write_register32(const uint16_t reg, const uint32_t v)
{
    TRANSACTION_GUARD();
    return writeRegister32BE(to_write_reg(reg), v, false);
}

uint32_t UnitST25R3916::wait_for_interrupt(const uint32_t irq, const uint32_t timeout_ms, bool include_error)
{
    auto timeout_at           = m5::utility::millis() + timeout_ms;
    const uint32_t error_bits = include_error ? 0x0000FF00 : 0;
    do {
        if (_interrupt_occurred) {
            uint32_t v{};
            if (readInterrupts(v)) {
                _irq_flags |= v;
            }
            _interrupt_occurred = false;
        }
        if (_irq_flags & (irq | error_bits)) {
            auto ret   = _irq_flags & (irq | error_bits);
            _irq_flags = 0;
            return ret;
        }
    } while (m5::utility::millis() <= timeout_at);
    return I_nre32;  // Timeout
}

bool UnitST25R3916::wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size)
{
    auto irq               = wait_for_interrupt(I_rxe32, timeout_ms);
    const uint16_t reqSize = required_size ? required_size : 1;
    if (is_irq32_received(irq)) {
        return true;
    }

    // Check the FIFO size in case I_rxe doesn't arrive
    auto timeout_at = m5::utility::millis() + timeout_ms;
    uint16_t bytes{};
    uint8_t bits{};
    do {
        readFIFOSize(bytes, bits);
        if (bytes >= reqSize) {
            break;
        }
        m5::utility::delay(1);
    } while (m5::utility::millis() <= timeout_at);
    readFIFOSize(bytes, bits);
    return bytes >= reqSize;
}

Type UnitST25R3916::identify_mifare_type(const UID& uid)
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
    M5_LIB_LOGE("---- GET_VERSION %02X", sak);
    if (!get_version(ver)) {
        // UltraLight or UltraLightC or NTAG203
        uint16_t discard{};
#if 0
        // Re-activate if get_version has been failed (PICC goes into IDLE mode)
        req_wup_device(discard, true /* REQA*/);
        if (!select(uid)) {
            M5_LIB_LOGE("Faild to re-select %s", uid.uidAsString().c_str());
            return Type::Unknown;
        }
#endif
        uint8_t des[] = {m5::stl::to_underlying(Command::AUTHENTICATE_1), 0x00};
        uint8_t rbuf[16]{};
        uint16_t rx_len = sizeof(rbuf);
        M5_LIB_LOGE("---- 3DES");
        if (transceive(rbuf, rx_len, des, sizeof(des), TIMEOUT_3DES)) {
            if (rbuf[0] == 0xAF) {
                return Type::MIFARE_UltraLightC;
            }
        }
#if 1
        // Re-activate if transceive has been failed (PICC goes into IDLE mode)
        req_wup_device(discard, true /* REQA*/);
        return select(uid) ? Type::MIFARE_UltraLight : Type::Unknown;
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

bool UnitST25R3916::get_version(uint8_t info[10])
{
    uint8_t gv[1]   = {0x60};
    uint16_t rx_len = 10;
    return transceive(info, rx_len, gv, sizeof(gv), TIMEOUT_GET_VERSION);
}

bool UnitST25R3916::dump(const UID& uid, const Key& key)
{
    if (uid.isClassic()) {
        return dump_sector_structure(uid, key);
    } else if (uid.canNFC()) {
        M5_LIB_LOGE("NFC-A ISO14443-A");
        //        return dump_page_structure(uid.blocks);
    }
    return false;
}

bool UnitST25R3916::dump_sector_structure(const UID& uid, const Key& key)
{
    uint8_t sectors = get_number_of_sectors(uid.type);
    if (!sectors) {
        return false;
    }

    puts(
        "Sec[Blk]:00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F [Access]\n"
        "-----------------------------------------------------------------");

    for (int_fast8_t sector = 0; sector < sectors; ++sector) {
        auto sblock = get_sector_trailer_block_from_sector(sector);
        auto result = mifareAuthenticateA(uid, sblock, key) && dump_sector(sector);

        printf("%2d) %s\n", sector, result ? "AUTH OK" : "ERROR");

        if (!result) {
            //            printf("%2d) ERROR\n", sector);
            /////>>>>> test exit
            return false;
        }
        hltA();
        uint16_t discard{};
        req_wup_device(discard, false);
        select(uid);
    }
    return true;
}

bool UnitST25R3916::dump_sector(const uint8_t sector)
{
    // Sector 0~31 has 4 blocks, 32-39 has 16 blocks (4K)
    const uint8_t blocks = (sector < 32) ? 4U : 16U;
    const uint8_t base   = (sector < 32) ? sector * blocks : 128U + (sector - 32) * blocks;

    uint8_t sbuf[16]{};
    uint16_t slen{16};
    uint8_t permissions[4]{};                 // [3] is sector trailer
    const uint8_t saddr = base + blocks - 1;  //  sector traler

    // Read sector trailer
    if (!read_block(sbuf, slen, saddr)) {
        return false;
    }

    bool error = !decode_access_bits(permissions, sbuf + 6 /* Access bits offset */);
    //    M5_LIB_LOGW(">> S:%u => %u [%u,%u,%u,%u]", sector, saddr, permissions[0], permissions[1], permissions[2],
    //                permissions[3]);

    // Data
    for (int_fast8_t i = 0; i < blocks - 1; ++i) {
        uint8_t dbuf[16]{};
        uint16_t dlen{16};
        uint8_t daddr = base + i;
        if (!read_block(dbuf, dlen, daddr)) {
            return false;
        }
        const uint8_t poffset      = (blocks == 4) ? i : i / 5;
        const uint8_t permission   = permissions[poffset];
        const bool show_permission = (blocks == 4) ? true : (i % 5) == 0;
        dump_block(dbuf, base + i, (i == 0) ? sector : -1, show_permission ? permission : 0xFF, error,
                   is_value_block_permission(permission));
    }
    // Sector trailer
    dump_block(sbuf, saddr, -1, permissions[3], error);

    return true;
}

bool UnitST25R3916::write_noresponse_timeout(const uint32_t ms)
{
    uint8_t timer_ctrl{};
    if (readTimerAndEMVControl(timer_ctrl)) {
        const bool fc4096  = (timer_ctrl & 1);
        const uint16_t nrt = calculate_nrt(ms, fc4096);
        return writeNoResponseTimer(nrt);
    }
    return false;
}

bool UnitST25R3916::mifareAuthenticateA(const UID& uid, const uint8_t sblock, const Key& mkey)
{
    return mifare_authenticate(Command::AUTH_WITH_KEY_A, uid, sblock, mkey);
}

bool UnitST25R3916::mifare_authenticate(const Command cmd, const UID& uid, const uint8_t block, const Key& mkey)
{
    if ((cmd != Command::AUTH_WITH_KEY_A && cmd != Command::AUTH_WITH_KEY_B) || uid.size == 0 ||
        uid.type == Type::Unknown) {
        return false;
    }

    // 3-pass mutual authentication

    // Encrypted?
    const uint64_t key48 = key_to64(mkey.data());

    // Send AUTH command (Plane) and receive token RB (Nt)
    uint8_t auth_frame[2] = {m5::stl::to_underlying(cmd), block};
    uint8_t RB[4]{};
    uint16_t rlen{4};
    if (!writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
        !transceive(RB, rlen, auth_frame, sizeof(auth_frame), TIMEOUT_AUTH1)) {
        M5_LIB_LOGE("Failed to send AUTH(plain) %u", rlen);
        return false;
    }

    //    M5_LIB_LOGE("RECV RB:");
    //    m5::utility::log::dump(RB, rlen, false);

    // Send encrypt token AB (Nr, Ar)
    uint8_t tail4[4]{};
    uid.tail4(tail4);
    const uint32_t u32 = array_to32(tail4);
    const uint32_t Nt  = array_to32(RB);
    const uint32_t Nr  = esp_random();
    // const uint32_t Ar   = suc_k(swap_endian_32(Nt), 2);  // suc2
    // const uint32_t suc3 = suc_k(swap_endian_32(Nt), 3);  // suc3
    uint32_t Ar{}, suc3{};
    suc_23(swap_endian_32(Nt), Ar, suc3);

    uint8_t AB[8 + 1 /*parity*/]{};
    M5_LIB_LOGE("Auth:%u  mkey:%llX uid:%X Nt:%X Nr:%X Ar:%X", block, key48, u32, Nt, Nr, Ar);

    _crypto1.init(key48);
    _crypto1.inject(u32, Nt);
    uint8_t parity = _crypto1.encrypt(AB, Nr, Ar);
    AB[8]          = parity;

    // M5_LIB_LOGE("SEND AB:");

    uint8_t bitstream[9] = {0};
    uint32_t bitpos      = 0;
    auto put_bit         = [&](uint8_t b) {
        uint32_t byte = bitpos >> 3;
        uint8_t off   = bitpos & 7;
        if (b) bitstream[byte] |= (1u << off);
        bitpos++;
    };
    for (int i = 0; i < 8; ++i) {
        uint8_t v = AB[i];
        for (int k = 0; k < 8; ++k) put_bit((v >> k) & 1u);  // LSB→MSB
        put_bit((parity >> i) & 1u);
    }

    // m5::utility::log::dump(AB, sizeof(AB), false);
    // m5::utility::log::dump(bitstream, sizeof(bitstream), false);

    write_noresponse_timeout(TIMEOUT_AUTH2);

    auto write_8 = [&]() {
        if (!writeSettingsISO14443A(no_tx_par | no_rx_par) || !writeAuxiliaryDefinition(no_crc_rx) ||
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||  //
            !writeFIFO(AB, 8) || !writeNumberOfTransmittedBytes(8, 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {              //
            return false;
        }
        return true;
    };
    auto write_9AB = [&]() {
        if (!writeSettingsISO14443A(no_tx_par | no_rx_par) || !writeAuxiliaryDefinition(no_crc_rx /*| 0x04*/) ||
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                    //
            !writeFIFO(AB, sizeof(AB)) || !writeNumberOfTransmittedBytes(sizeof(AB), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            return false;
        }
        return true;
    };
    //  Using It!
    auto write_9bs = [&]() {
        if (!writeSettingsISO14443A(no_tx_par /*| no_rx_par*/) || !writeAuxiliaryDefinition(no_crc_rx /*| 0x04*/) ||
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
            !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            M5_LIB_LOGE("Failed to AUTH(encrypt)");
            return false;
        }
        return true;
    };

    auto write_stream_8 = [&]() {
        if (!writeInitiatorOperationMode(InitiatorOperationMode::SubCarrierStream, 0x00 /* nfc_ar01 */) ||
            !writeStreamModeDefinition(0x40 /* scf10b 848 */ | 0x18 /* scp 11b 8 */) || !clearInterrupts() ||
            !writeDirectCommand(CMD_CLEAR_FIFO) ||                        //
            !writeFIFO(AB, 8) || !writeNumberOfTransmittedBytes(8, 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            return false;
        }
        return true;
    };
    auto write_stream_9AB = [&]() {
        if (!writeInitiatorOperationMode(InitiatorOperationMode::SubCarrierStream, 0x00 /* nfc_ar01 */) ||
            !writeStreamModeDefinition(0x40 /* scf10b 848 */ | 0x18 /* scp 11b 8 */) || !clearInterrupts() ||
            !writeDirectCommand(CMD_CLEAR_FIFO) ||                                          //
            !writeFIFO(AB, sizeof(AB)) || !writeNumberOfTransmittedBytes(sizeof(AB), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            return false;
        }
        return true;
    };
    auto write_stream_9bs = [&]() {
        if (!writeInitiatorOperationMode(InitiatorOperationMode::SubCarrierStream, 0x00 /* nfc_ar01 */) ||
            !writeStreamModeDefinition(0x40 /* scf10b 848 */ | 0x18 /* scp 11b 8 */) || !clearInterrupts() ||
            !writeDirectCommand(CMD_CLEAR_FIFO) ||                                                               //
            !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            return false;
        }
        return true;
    };

    auto write_stream_19bs = [&]() {
        uint8_t buf[2]{};
        if (!writeSettingsISO14443A(no_tx_par | no_rx_par) || !writeAuxiliaryDefinition(no_crc_rx /*| 0x04*/)) {
            return false;
        }

        for (uint8_t i = 0; i < 8; ++i) {
            buf[0] = AB[i];
            buf[1] = (parity >> (8 - i)) & 1;
            if (!clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||             //
                !writeFIFO(buf, sizeof(buf)) || !writeNumberOfTransmittedBytes(1, 1) ||  //
                !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
                return false;
            }
        }
        return true;
    };

    static int func = 2;
    switch (func) {
        case 0:
            M5_LIB_LOGE(">>> write_8");
            if (!write_8()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 1:
            M5_LIB_LOGE(">>> write_9AB");
            if (!write_9AB()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 2:
            // M5_LIB_LOGE(">>> write_9bs");
            if (!write_9bs()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 3:
            M5_LIB_LOGE(">>> write_stream_8");
            if (!write_stream_8()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 4:
            M5_LIB_LOGE(">>> write_stream_9AB");
            if (!write_stream_9AB()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 5:
            M5_LIB_LOGE(">>> write_stream_9bs");
            if (!write_stream_9bs()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 6:
            M5_LIB_LOGE(">>> write_stream_19bs");
            if (!write_stream_19bs()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
    }
        //    if (++func > 6) func = 0;

#if 0
    //    auto irq = wait_for_interrupt(I_rxs32 | I_rxe32 | I_nre32, TIMEOUT_AUTH2);
    auto irq = wait_for_interrupt(I_rxs32 | I_rxe32, TIMEOUT_AUTH2);
    if (!(irq & (I_rxs32 | I_rxe32))) {
        M5_LIB_LOGE("Failed to tranceive(encrypt) %08X", irq);
        return false;
    }
    if (!(irq & I_rxe32)) {  // The I_rxe bit may not be set
        auto timeout_at = m5::utility::millis() + TIMEOUT_AUTH2;
        uint16_t bytes{};
        uint8_t bits{};
        do {
            readFIFOSize(bytes, bits);
            if (bytes == 4) {
                break;
            }
            m5::utility::delay(1);
        } while (m5::utility::millis() <= timeout_at);
    }
#else
    if (!wait_for_FIFO(TIMEOUT_AUTH2, 4)) {
        M5_LIB_LOGE("Timeout");
    }
#endif

    // Receive token BA (At)
    uint8_t BA[4]{};
    uint16_t actual{};
    if (!readFIFO(actual, BA, sizeof(BA)) || actual != 4) {
        M5_LIB_LOGE("Failed to readFIFO %u", actual);
        return false;
    }

    // M5_LIB_LOGE("RECV BA:%u", actual);
    //     m5::utility::log::dump(BA, actual, false);

    uint8_t Atp[4]{};
    for (int i = 0; i < 4; ++i) {
        Atp[i] = BA[i] ^ _crypto1.step8(0);
    }
    uint32_t Atp32 = (uint32_t)Atp[0] | ((uint32_t)Atp[1] << 8) | ((uint32_t)Atp[2] << 16) | ((uint32_t)Atp[3] << 24);
    // M5_LIB_LOGE(">>>>>>> Atp:%x suc3:%x count:%u", Atp32, suc3, _crypto1._count);
    return Atp32 == suc3;
}

// --------------------------------
// class CapST25R3916
const char CapST25R3916::name[] = "CapST25R3916";
const types::uid_t CapST25R3916::uid{"CapST25R39162"_mmh3};
const types::attr_t CapST25R3916::attr{attribute::AccessSPI};

bool CapST25R3916::begin()
{
    // Disbale ST25R3816
    pinMode(PIN_CS_ST25R3916, OUTPUT);
    digitalWrite(PIN_CS_ST25R3916, HIGH);

    // Attach interrupt
    pinMode(PIN_ST25R3916_IRQ, INPUT_PULLDOWN);
    attachInterruptArg(digitalPinToInterrupt(PIN_ST25R3916_IRQ), &UnitST25R3916::on_irq, this, RISING);

    return UnitST25R3916::begin();
}

}  // namespace unit
}  // namespace m5
