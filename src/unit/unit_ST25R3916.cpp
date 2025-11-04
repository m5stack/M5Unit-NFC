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
#include <thread>

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

//
constexpr uint32_t TIMEOUT_REQ_WUP{4};
constexpr uint32_t TIMEOUT_SELECT{4};
constexpr uint32_t TIMEOUT_ANTICOLL{8};
constexpr uint32_t TIMEOUT_HALT{2};
constexpr uint32_t TIMEOUT_GET_VERSION{5};
constexpr uint32_t TIMEOUT_3DES{10};
constexpr uint32_t TIMEOUT_AUTH1{1};
constexpr uint32_t TIMEOUT_AUTH2{10};
constexpr uint32_t TIMEOUT_READ{4};
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
// constexpr uint16_t io_config12_spi{miso_pd1 | miso_pd2 | io_drv_lvl};

float regulated_voltages(const uint8_t regulator_display_reg_value, const bool voltage5V = false)
{
    auto rv = (regulator_display_reg_value >> 4) & 0x0F;
    if (voltage5V) {
        return 3.6f + 0.1f * rv;
    }
    return (rv < 5) ? std::numeric_limits<float>::quiet_NaN() : 2.4f + (0.1f * (rv - 5));
}

uint16_t calculate_nrt(const uint32_t ms, const bool nrt_step)
{
    auto step_sec      = (nrt_step ? 4096 : 64) / 13560000.f;
    uint32_t nrt       = (uint32_t)std::round((ms / 1000.f) / step_sec);
    const uint32_t max = nrt_step ? 0xFFFF : 0xF857;
    if (nrt > max) {
        nrt = max;
    }
    //    M5_LIB_LOGE(">>>> %ums fc4096:%u => %04X", ms, nrt_step, nrt);
    return nrt;
}

//
uint8_t calculate_mrt(const uint32_t us, const bool mrt_step)
{
    constexpr float fc  = 13.56e6f;  // 13.56 MHz
    const uint32_t step = mrt_step ? 512 : 64;

    float mrt_f  = (us * fc) / (1e6f * step);
    uint32_t mrt = static_cast<uint32_t>(std::round(mrt_f));

    mrt = std::max(std::min(mrt, 255u), 4u);  // clamp 4...255
    // auto actual = mrt * (step / fc) * 1e6f;
    // M5_LIB_LOGE("MRT: %u us -> reg=%02X (%0.2f us)", us, mrt, actual);
    return static_cast<uint8_t>(mrt);
}

inline bool has_irq32_error(const uint32_t irq32)
{
    return irq32 & 0x0000FF00;
}

inline bool is_irq32_timeout(const uint32_t irq32)
{
    return irq32 & I_nre32;
}

inline bool is_irq32_rxe(const uint32_t irq32)
{
    return irq32 & I_rxe32;
}

inline bool is_irq32_rxs(const uint32_t irq32)
{
    return irq32 & I_rxs32;
}

inline bool is_irq32_txe(const uint32_t irq32)
{
    return irq32 & I_txe32;
}

inline bool is_irq32_collision(const uint32_t irq32)
{
    return irq32 & I_col32;
}

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

// Octal coded binary for bit representation
inline uint32_t OCB(const uint8_t c)
{
    // printf("%08o", OCB(0x2d)); => 00101101
    return (c & 1) | (c & 2) << 2 | (c & 4) << 4 | (c & 8) << 6 | (c & 16) << 8 | (c & 32) << 10 | (c & 64) << 12 |
           (c & 128) << 14;
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

//
#if 0
    uint8_t a_table[] = {
        /*
        0x07, 0x3C, 0x83, 0x08, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x00, 0x00, 0x08, 0x2D, 0xD8, 0x00, 0x0C,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFB, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        */
        0x07, 0x3C, 0xCB, 0x08, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x00, 0x03, 0x08, 0x2D, 0x00, 0x00, 0x0E,
        0x00, 0x23, 0x20, 0x02, 0xC8, 0x80, 0x87, 0xA6, 0x0F, 0x7B, 0x00, 0x20, 0x00, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x38, 0x00, 0xDF, 0x82, 0x82, 0x70, 0x5F, 0x13, 0x02, 0x00, 0x33, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    struct B {
        uint16_t reg;
        uint8_t val;
    } b_table[] = {
        {0x05, 0x40}, {0x06, 0x00}, {0x0B, 0x0C}, {0x0C, 0x51}, {0x0D, 0x00}, {0x0F, 0x00}, {0x15, 0x00}, {0x28, 0x10},
        {0x29, 0x7C}, {0x2A, 0x80}, {0x2B, 0x04}, {0x2C, 0xD0}, {0X30, 0x40}, {0x31, 0x03}, {0x32, 0x40}, {0x33, 0x03},
    };

    uint8_t r{};
    for (auto&& v : a_table) {
        write_register8(r++, v);
    }
    for (auto&& b : b_table) {
        write_register8(b.reg, b.val);
    }

#endif

#if 0
    write_register8((uint8_t)0x08, 0x5D);
    write_register8((uint8_t)0x09, 0x03);
    write_register8((uint8_t)0x12, 0x20);
    write_register8((uint8_t)0x13, 0x02);

    write_register8((uint8_t)0x25, 0xDF);
    write_register8((uint8_t)0x26, 0x82);
    write_register8((uint8_t)0x27, 0x82);

    write_register8((uint8_t)0x28, 0x70);
    write_register8((uint8_t)0x29, 0x5F);
    write_register8((uint8_t)0x2A, 0x13);
    write_register8((uint8_t)0x2B, 0x02);

    write_register8((uint8_t)0x00, 0x07);
    write_register8((uint8_t)0x01, 0x3C);
    write_register8((uint8_t)0x02, 0xCB);
    

    write_register8((uint16_t)0x05, 0x40);
    write_register8((uint16_t)0x0C, 0x51);
    write_register8((uint16_t)0x15, 0x00);
    write_register8((uint16_t)0x2A, 0x80);
    write_register8((uint16_t)0x2C, 0xD0);
    write_register8((uint16_t)0x30, 0x40);
    write_register8((uint16_t)0x31, 0x03);
    write_register8((uint16_t)0x32, 0x40);
    write_register8((uint16_t)0x33, 0x03);
#endif

    return true;
}

void UnitST25R3916::update(const bool /*force*/)
{
    if (_interrupt_occurred) {
        _interrupt_occurred = false;
        uint32_t v{};
        if (readInterrupts(v)) {
            _irq_flags |= v;
        }
    }
}

bool UnitST25R3916::req_wup_device(uint16_t& atqa, const bool req)
{
    _encrypted = false;
    atqa       = 0;
    //    constexpr uint8_t mask = ~(I_rxe | I_col);
    constexpr uint32_t wait{I_rxs32 | I_rxe32 | I_col32};

    // REQA or WUPA
    if (!write_noresponse_timeout(TIMEOUT_REQ_WUP) ||  //
        !writeSettingsISO14443A(antcl) || !writeAuxiliaryDefinition(no_crc_rx) ||
        //        writeMaskMainInterrupt(mask) && writeMaskTimerAndNFCInterrupt(~I_nre) &&//
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||
        !writeDirectCommand(req ? CMD_TRANSMIT_REQA : CMD_TRANSMIT_WUPA)) {
        M5_LIB_LOGE("Failed to %s", req ? "REQA" : "WUPA");
        return false;
    }
    auto irq = wait_for_interrupt(wait, TIMEOUT_REQ_WUP);
    if (!(irq & wait)) {
        return false;
    }
    if (wait_for_FIFO(TIMEOUT_REQ_WUP, 2)) {
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

bool UnitST25R3916::anti_collision(uint8_t rbuf[5], const uint8_t lv)
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
        if (!transceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
            M5_LIB_LOGE("Failed to select");
            return false;
        }
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
    uint16_t rx_len{3};
    if (!writeSettingsISO14443A(0x00 /*standard*/) || !writeAuxiliaryDefinition(0) ||
        !transceive(rbuf, rx_len, select_frame, sizeof(select_frame), TIMEOUT_SELECT) || rx_len != 3) {
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

bool UnitST25R3916::hltA()
{
    const uint8_t hlta[2] = {m5::stl::to_underlying(Command::HLTA), 0x00};
    if (!write_noresponse_timeout(TIMEOUT_HALT) || !writeSettingsISO14443A(0x00 /*standard*/) ||
        !writeAuxiliaryDefinition(0) ||
        //! writeMaskMainInterrupt(~I_txe) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) || !writeFIFO(hlta, sizeof(hlta)) ||
        !writeNumberOfTransmittedBytes(sizeof(hlta), 0) || !writeDirectCommand(CMD_TRANSMIT_WITH_CRC)) {
        return false;
    }
    _encrypted = false;
    // No response is coming back, so need to confirm if it was sent
    auto irq = wait_for_interrupt(I_txe32, TIMEOUT_HALT);
    return is_irq32_txe(irq);
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

bool UnitST25R3916::transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                       const uint32_t timeout_ms)
{
    if (!rx || !rx_len || !tx || !tx_len) {
        return false;
    }

    uint8_t buf[tx_len + ((tx_len + 7) >> 3)]{};

    return false;
}

bool UnitST25R3916::read_block_encrypted(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    uint8_t cmd[4] = {m5::stl::to_underlying(Command::READ), addr};
    m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);
    //    m5::utility::CRC16 crc16(0x6363, 0x1021, false, false, 0);
    auto crc = crc16.range(cmd, 2);
    cmd[2]   = crc & 0xFF;
    cmd[3]   = crc >> 8;

    uint8_t enc_tx[4]{};
    uint32_t parity = _crypto1.encrypt(enc_tx, cmd, sizeof(cmd));

    uint8_t bitstream[5]{};
    append_parity(bitstream, sizeof(bitstream), enc_tx, sizeof(enc_tx), parity);

    // Send
    // M5_LIB_LOGE("Send: parity:%04X cnt:%u", parity, _crypto1._count);
    //    m5::utility::log::dump(cmd, 4, false);
    //    m5::utility::log::dump(enc_tx, 4, false);
    //    m5::utility::log::dump(bitstream, 5, false);

    if (!write_noresponse_timeout(TIMEOUT_READ) ||  //
        !writeSettingsISO14443A(no_tx_par /*| no_rx_par*/) || !writeAuxiliaryDefinition(no_crc_rx /*| 0x04*/) ||
        !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||  //
        !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(4, 4) ||
        !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
        M5_LIB_LOGE("Failed to send");
        return false;
    }

    // Read
    if (!wait_for_FIFO(TIMEOUT_READ, 18)) {
        M5_LIB_LOGE("Timeout");
        return false;
    }

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

bool UnitST25R3916::read_block(uint8_t* rx, uint16_t& rx_len, const uint8_t addr)
{
    uint8_t cmd[2] = {m5::stl::to_underlying(Command::READ), addr};
    if (!writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
        !transceive(rx, rx_len, cmd, sizeof(cmd), TIMEOUT_READ)) {
        M5_LIB_LOGE("Failed to transcive");
        return false;
    }
    return true;
}

bool UnitST25R3916::ntag_fast_read(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    uint8_t cmd[3] = {m5::stl::to_underlying(Command::FAST_READ), spage, epage};
    if (!writeSettingsISO14443A(0x00 /* standard*/) || !writeAuxiliaryDefinition(0) ||
        !transceive(rx, rx_len, cmd, sizeof(cmd))) {
        M5_LIB_LOGE("Failed to transcive");
        return false;
    }
    return true;
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
    uint8_t value = m5::stl::to_underlying(mode);  // targ 0 mode
    value |= (0x07 & optional);                    // optional bits
    return writeModeDefinition(value);
}

bool UnitST25R3916::writeTargetOperationMode(const TargetOperationMode mode, const uint8_t optional)
{
    uint8_t value = m5::stl::to_underlying(mode) | 0x80;  // targ 1 mode
    value |= (0x07 & optional);                           // optional bits
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
            _interrupt_occurred = false;
            uint32_t v{};
            if (readInterrupts(v)) {
                _irq_flags |= v;
            }
        }
        if (_irq_flags & irq) {
            uint32_t ret = _irq_flags & irq;
            _irq_flags   = 0;
            return ret;
        }
        std::this_thread::yield();
    } while (m5::utility::millis() <= timeout_at);
    return I_nre32;  // Timeout
}

bool UnitST25R3916::wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size)
{
    auto irq               = wait_for_interrupt(I_rxe32 | I_rxs32, timeout_ms);
    const uint16_t reqSize = required_size ? required_size : 1;

    if (is_irq32_rxe(irq)) {
        return true;
    }
    // M5_LIB_LOGE("IRQ:%08X %u", irq, timeout_ms);

    if (is_irq32_rxs(irq)) {
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
    return false;
}

Type UnitST25R3916::identify_nfca_type(const UID& uid)
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
    uint8_t gv[1]   = {m5::stl::to_underlying(Command::GET_VERSION)};
    uint16_t rx_len = 10;
    return transceive(info, rx_len, gv, sizeof(gv), TIMEOUT_GET_VERSION);
}

bool UnitST25R3916::write_noresponse_timeout(const uint32_t ms)
{
    uint8_t timer_ctrl{};
    if (readTimerAndEMVControl(timer_ctrl)) {
        const bool nstep   = (timer_ctrl & nrt_step);
        const uint16_t nrt = calculate_nrt(ms, nstep);
        return writeNoResponseTimer(nrt);
    }
    return false;
}

bool UnitST25R3916::write_mask_receiver_timer(const uint32_t us)
{
    uint8_t temv{};
    if (readTimerAndEMVControl(temv)) {
        const bool mstep = temv & mrt_step;
        return writeMaskReceiveTimer(calculate_mrt(us, mstep));
    }
    return false;
}

bool UnitST25R3916::write_squelch_timer(const uint32_t us)
{
    uint8_t temv{};
    if (readTimerAndEMVControl(temv)) {
        const bool mstep = temv & mrt_step;
        // squelch timer same as MRT
        return writeSquelchTimer(calculate_mrt(us, mstep));
    }
    return false;
}

bool UnitST25R3916::mifare_authenticate(const Command cmd, const UID& uid, const uint8_t block, const Key& mkey,
                                        const bool encrypted)
{
    if ((cmd != Command::AUTH_WITH_KEY_A && cmd != Command::AUTH_WITH_KEY_B) || uid.size == 0 ||
        uid.type == Type::Unknown) {
        return false;
    }

    // 3-pass mutual authentication

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
    m5::utility::delayMicroseconds(100);  // Wait for AUTH <-> Sebd AB (At least 86.4 us)

    //M5_LIB_LOGE("RECV RB:");
    //m5::utility::log::dump(RB, rlen, false);

    // Send encrypt token AB (Nr, Ar)
    uint8_t tail4[4]{};
    uid.tail4(tail4);
    const uint32_t u32 = array_to32(tail4);
    const uint32_t Nt  = array_to32(RB);
    const uint32_t Nr  = esp_random();
    // const uint32_t Ar   = suc_k(swap_endian_32(Nt), 2);  // suc2
    // const uint32_t suc3 = suc_k(swap_endian_32(Nt), 3);  // suc3
    uint32_t Ar{}, suc3{};
    //    suc_23(swap_endian_32(Nt), Ar, suc3);
    suc_23(m5::stl::byteswap(Nt), Ar, suc3);

    uint8_t AB[8 + 1 /*parity*/]{};
    M5_LIB_LOGD("Auth:%u  mkey:%llX uid:%X Nt:%X Nr:%X Ar:%X", block, key48, u32, Nt, Nr, Ar);

    _crypto1.init(key48);
    _crypto1.inject(u32, Nt);
    //    uint8_t parity = _crypto1.encrypt(AB, Nr, Ar, Nt);
    uint8_t parity = _crypto1.encrypt(AB, Nr, Ar);
    AB[8]          = parity;

    // M5_LIB_LOGE("SEND AB:");

    uint8_t bitstream[9 /* AB 8bytes + encrypt parity 1(8bits)] */]{0};
    append_parity(bitstream, sizeof(bitstream), AB, 8, parity);

    // m5::utility::log::dump(AB, sizeof(AB), false);
    // m5::utility::log::dump(bitstream, sizeof(bitstream), false);

    write_noresponse_timeout(TIMEOUT_AUTH2);

#if 0
    // MRT/SQT
    if (!write_mask_receiver_timer(0) || !write_squelch_timer(0)) {
        M5_LIB_LOGE("Failed to MRT/SQT");
        return false;
    }
    uint8_t mrt{}, sqt{};
    readMaskReceiveTimer(mrt);
    readSquelchTimer(sqt);
    M5_LIB_LOGE("====== MRT:%02X SQT:%02X", mrt, sqt);
#endif

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
    auto write_9bs = [&]() {
        if (!writeSettingsISO14443A(no_tx_par) || !writeAuxiliaryDefinition(no_crc_rx) ||                        //
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
            !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            M5_LIB_LOGE("Failed to AUTH(encrypt)");
            return false;
        }
        return true;
    };

    auto write_9bs_2 = [&]() {
        if (!writeSettingsISO14443A(no_tx_par) || !writeAuxiliaryDefinition(0) ||                                //
            !clearInterrupts() || !writeDirectCommand(CMD_CLEAR_FIFO) ||                                         //
            !writeFIFO(bitstream, sizeof(bitstream)) || !writeNumberOfTransmittedBytes(sizeof(bitstream), 0) ||  //
            !writeDirectCommand(CMD_TRANSMIT_WITHOUT_CRC)) {
            M5_LIB_LOGE("Failed to AUTH(encrypt)");
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
            M5_LIB_LOGE(">>>> write_8");
            if (!write_8()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 1:
            M5_LIB_LOGE(">>>> write_9AB");
            if (!write_9AB()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 2:
            //            M5_LIB_LOGE(">>>> write_9bs");
            if (!write_9bs()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        case 3:
            M5_LIB_LOGE(">>>> write_9bs_2");
            if (!write_9bs_2()) {
                M5_LIB_LOGE(">>>> Failed to send");
                return false;
            }
            break;
        default:
            break;
    }
    //    if (++func > 2) func = 0;

    if (!wait_for_FIFO(TIMEOUT_AUTH2, 4)) {
        M5_LIB_LOGE("Timeout");
    }

    // Receive token BA (At)
    uint8_t BA[4 + 2]{};
    uint16_t actual{};
    if (!readFIFO(actual, BA, sizeof(BA)) || actual != 4) {
        M5_LIB_LOGE("Failed to readFIFO %u", actual);
        return false;
    }

    //    M5_LIB_LOGE("RECV BA:%u", actual);
    // m5::utility::log::dump(BA, actual, false);

    uint8_t At2[4]{};
    for (int i = 0; i < 4; ++i) {
        At2[i] = BA[i] ^ _crypto1.step8(0);
    }
    uint32_t At32 = (uint32_t)At2[0] | ((uint32_t)At2[1] << 8) | ((uint32_t)At2[2] << 16) | ((uint32_t)At2[3] << 24);
    //    M5_LIB_LOGE(">>>>>>> At32:%x suc3:%x count:%u", At32, suc3, _crypto1._count);
    _encrypted = (At32 == suc3);
    return _encrypted;
}

void UnitST25R3916::dumpRegister()
{
    M5_LIB_LOGI("SpaceA");
    for (uint8_t r = REG_IO_CONFIGURATION_1; r <= REG_IC_IDENTITY; ++r) {
        uint8_t v{};
        read_register8(r, v);
        M5_LIB_LOGI("Reg[0X%02X]:0X%02X:%08o", r, v, OCB(v));
    }

    constexpr uint16_t b_table[] = {
        REG_EMD_SUPPRESSION_CONFIGURATION,
        REG_SUBCARRIER_START_TIMER,
        REG_P2P_RECEIVER_CONFIGURATION,
        REG_CORRELATOR_CONFIGURATION_1,
        REG_CORRELATOR_CONFIGURATION_2,
        REG_SQUELCH_TIMER,
        REG_NFC_FIELD_ON_GUARD_TIMER,
        REG_AUXILIARY_MODULATION_SETTING,
        REG_TX_DRIVER_TIMING,
        REG_RESISTIVE_AM_MODULATION,
        REG_TX_DRIVER_TIMING_DISPLAY,
        REG_REGULATOR_DISPLAY,
        REG_OVERSHOOT_PROTECTION_CONFIGURATION_1,
        REG_OVERSHOOT_PROTECTION_CONFIGURATION_2,
        REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1,
        REG_UNDERSHOOT_PROTECTION_CONFIGURATION_2,
    };
    M5_LIB_LOGI("SpaceB");
    for (auto&& r : b_table) {
        uint8_t v{};
        read_register8(r, v);
        M5_LIB_LOGI("Reg[0X%02X]:0X%02X:%08o", r, v, OCB(v));
    }
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
