/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916.cpp
  @brief ST25R3916 Unit for M5UnitUnified
*/
//#include <Arduino.h>
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

// For noresoponse timer
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

// For mask receiver timer and squelch timer (MRT, SRT)
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

    //
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
    /*
    if (_interrupt_occurred) {
        _interrupt_occurred = false;
        uint32_t v{};
        if (readInterrupts(v)) {
            _irq_flags |= v;
        }
    }
    */
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
    auto timeout_at = m5::utility::millis() + timeout_ms;
    uint32_t flags{};
    do {
        if (_interrupt_occurred) {
            _interrupt_occurred = false;
            uint32_t v{};
            if (readInterrupts(v)) {
                flags |= v;
            }
        }
        if (flags & irq) {
            return flags;
        }
        std::this_thread::yield();
    } while (m5::utility::millis() <= timeout_at);
    return flags | I_nre32;  // Timeout
}

bool UnitST25R3916::wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size)
{
    auto irq               = wait_for_interrupt(I_rxe32, timeout_ms);
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
