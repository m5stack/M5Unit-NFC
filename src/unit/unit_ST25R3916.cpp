/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916.cpp
  @brief ST25R3916 Unit for M5UnitUnified
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>
#include <thread>

using namespace m5::utility::mmh3;

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
// constexpr uint16_t io_config12_spi{miso_pd1 | miso_pd2};
constexpr uint16_t io_config12_spi{miso_pd1 | miso_pd2 | io_drv_lvl};

constexpr uint16_t get_i2c_thd_bits16(const uint32_t clk)
{
    return (clk >= 1000 * 1000u) ? (i2c_thd016 | i2c_thd116) : ((clk >= 400 * 1000u) ? i2c_thd016 : 0x0000);
}

float regulated_voltages(const uint8_t regulator_display_reg_value, const bool voltage5V = false)
{
    auto rv = (regulator_display_reg_value >> 4) & 0x0F;
    if (voltage5V) {
        return 3.6f + 0.1f * rv;
    }
    return (rv < 5) ? std::numeric_limits<float>::quiet_NaN() : 2.4f + (0.1f * (rv - 5));
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
    /*
    uint32_t v{};
    (void)u->readInterrupts(v);
    u->_stored_irq |= v;
    */
}

bool UnitST25R3916::begin()
{
    // Attach interrupt
    if (_cfg.using_irq) {
        M5_LIB_LOGD("Using IRQ:%u", _cfg.irq);
        //        pinMode(_cfg.irq, INPUT_PULLDOWN);
        pinMode(_cfg.irq, INPUT);
        attachInterruptArg(digitalPinToInterrupt(_cfg.irq), &UnitST25R3916::on_irq, this, RISING);
        _using_irq = true;
    }

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
    // 3) Settings
    uint16_t params{};
    if (adapter()->type() == Adapter::Type::I2C) {
        // I2C settings
        uint16_t i2c_thd = get_i2c_thd_bits16(component_config().clock);
        params           = i2c_thd | io_config12_i2c | (_cfg.vdd_voltage_5V ? 0x0000 : sup3v);
    } else if (adapter()->type() == Adapter::Type::SPI) {
        // SPI settings
        params = io_config12_spi | (_cfg.vdd_voltage_5V ? 0x0000 : sup3v);
    } else {
        M5_LIB_LOGE("Not support connection %u", adapter()->type());
        return false;
    }
    if (!writeIOConfiguration(params)) {
        M5_LIB_LOGE("Failed to writeIOConfiguration");
        return false;
    }

    // Antenna Settings
    // uint8_t txd{};
    //    if (!readTXDriver(txd) || !writeTXDriver((txd & 0x0F) | ((_cfg.tx_am_modulation & 0x0F) << 4))) {
    if (!writeTXDriver((_cfg.tx_am_modulation & 0x0F) << 4)) {  // d_rat, Use automatically, man slow
        M5_LIB_LOGE("Failed to TXDriver");
        return false;
    }

    //
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
    modify_bit_register8(REG_IO_CONFIGURATION_1, 0x07, 0x07);  // MCU_CLK disabled,No LF clock on MCU_CLK
    writeResistiveAMModulation(0x80);                          // Use minimum non-overlap
    set_bit_register8(REG_IO_CONFIGURATION_2, aat_en);         // Enable AAT D/A
    writeResistiveAMModulation(0x00);                          // Use normal non-overlap

    writeExternalFieldDetectorActivationThreshold(0x10 | 0x03);    // trg 105, rfe 205
    writeExternalFieldDetectorDeactivationThreshold(0x00 | 0x02);  // trg 75, rfe 150

    // clear_register_bit8(REG_AUXILIARY_MODULATION_SETTING, 0x20);   // External load modulation disabled
    modify_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, 0x05 << 4, 0xF0);  // FDT
    writePassiveTargetModulation(0x5F);                                            // ptm 17.1, pt HighZ
    writeEMDSuppressionConfiguration(0x40);  // start on the first four bits of the frame
    writeAntennaTuningControl1(0x82);
    writeAntennaTuningControl2(0x82);

    //
    set_bit_register8(REG_OPERATION_CONTROL, 0x03);  // 11: Enable external field detector automatically
    writeDirectCommand(CMD_CLEAR_FIFO);

    // 4) The internal voltage regulators have to be configuration
    // It is recommended to use direct command Adjust regulators to improve the system PSRR.
    if (!writeMaskInterrupts(0xFFFF00FF) && clearInterrupts()) {  // Mask all interrupts exclusive error
        M5_LIB_LOGE("Failed to writeMaskInterrupt");
        return false;
    }
    // Adjust regulators
    if (!enable_osc()) {
        M5_LIB_LOGE("Failed to enable_osc");
        return false;
    }
    writeMaskInterrupts(0);

    if (!writeDirectCommand(CMD_ADJUST_REGULATORS)) {
        M5_LIB_LOGE("Failed to CMD_ADJUST_REGULATORS");
        return false;
    }
    m5::utility::delay(5);  // Need wait

    // Check vdd voltage
    uint8_t value{};
    if (readRegulatorDisplay(value)) {
        M5_LIB_LOGV("Regulated voltages:%02X:%1.1fV", value, regulated_voltages(value, _cfg.vdd_voltage_5V));
    }

    return !_cfg.emulation ? configureNFCMode(_cfg.mode) : configureEmulationMode(_cfg.mode);
}

void UnitST25R3916::update(const bool /*force*/)
{
    // For I2C
    if (!_using_irq) {
        uint32_t v{};
        (void)readInterrupts(v);
        _stored_irq = _stored_irq | (v & _enabled_irq);
    }
}

bool UnitST25R3916::configureNFCMode(const m5::nfc::NFC mode)
{
    if (_cfg.emulation || mode == NFC::None) {
        return false;
    }

    if (!writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) ||            //
        !modify_bit_register8(REG_OPERATION_CONTROL, 0x00, wu)) {  // Disable wakeup mode
        return false;
    }

    bool ok{};
    switch (mode) {
        case m5::nfc::NFC::A:
            ok = configure_nfc_a();
            break;
        case m5::nfc::NFC::B:
            ok = configure_nfc_b();
            break;
        case m5::nfc::NFC::F:
            ok = configure_nfc_f();
            break;
        case m5::nfc::NFC::V:
            ok = configure_nfc_v();
            break;
        default:
            break;
    }

    /*
    write_noresponse_timeout(default_nrt_for(mode));
    write_mask_receiver_timer(default_mrt_for(mode));
    write_squelch_timer(default_sqt_for(mode));
    */
    if (ok) {
        M5_LIB_LOGV("Change NFC mode to %u", mode);
        _nfcMode = mode;
    }
    return ok;
}

bool UnitST25R3916::configureEmulationMode(const m5::nfc::NFC mode)
{
    if (!_cfg.emulation || mode == NFC::None) {
        return false;
    }
    if (NFCMode() == mode) {
        return true;
    }
    if (!writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) ||            //
        !modify_bit_register8(REG_OPERATION_CONTROL, 0x00, wu)) {  // Disable wakeup mode
        return false;
    }

    bool ok{};
    switch (mode) {
        case m5::nfc::NFC::A:
            ok = configure_emulation_a();
            break;
        case m5::nfc::NFC::F:
            ok = configure_emulation_f();
            break;
        default:
            M5_LIB_LOGE("Not supported");
            break;
    }
    if (ok) {
        M5_LIB_LOGV("Change emulation mode to %u", mode);
        _nfcMode = mode;
    }
    return ok;
}

bool UnitST25R3916::nfc_initial_field_on()
{
    uint8_t v{};
    if (!readOperationControl(v)) {
        return false;
    }
    if (v & tx_en) {
        M5_LIB_LOGE("Already tx_en");
        return false;
    }

    writeDirectCommand(CMD_NFC_INITIAL_FIELD_ON);
    m5::utility::delay(5);
    return modify_bit_register8(REG_OPERATION_CONTROL, tx_en | rx_en, 0x00);

#if 0
    
    if (!writeNFCFieldOnGuardTimer(0x00)) {
        return false;
    }
    if (!modify_bit_register8(REG_OPERATION_CONTROL, en_fd_manual_ca, en_fd_mask)) {
        return false;
    }

    //
    writeExternalFieldDetectorActivationThreshold(0x00);
    modify_bit_register8(REG_AUXILIARY_DEFINITION, 0x00, nfc_n_mask);

    clearInterrupts();

    uint32_t mask{};
    readMaskInterrupts(mask);
    mask |= (I_cac32 | I_cat32 | I_apon32);
    writeMaskInterrupts(mask);

    writeDirectCommand(CMD_NFC_INITIAL_FIELD_ON);

    bool ret{};
    auto irq = wait_for_interrupt(I_cac32 | I_cat32 | I_apon32, 10);
    M5_LIB_LOGE("IRQ:%08X", irq);
    if (irq & I_cac32) {
        M5_LIB_LOGE("RF Collison");
    } else if (irq & I_apon32) {
        irq = wait_for_interrupt(I_cat32, 10);
        M5_LIB_LOGE("    IRQ:%08X", irq);
        ret = (irq & I_cat32) != 0;
    } else {
        M5_LIB_LOGE("ERROR");
    }

    clearInterrupts();
    mask &= ~(I_cac32 | I_cat32 | I_apon32);
    //    writeMaskInterrupts(mask);
    disable_interrupts(mask);

    return ret && modify_bit_register8(REG_OPERATION_CONTROL, tx_en | rx_en, 0x00);
#endif
}

bool UnitST25R3916::writeDirectCommand(const uint8_t cmd, const uint8_t* data, uint32_t dlen)
{
    TRANSACTION_GUARD();
    return writeRegister(cmd, data, dlen, true /*I2C, SPI not used*/);
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
    _stored_irq = 0;
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

bool UnitST25R3916::writeBitrate(const m5::nfc::Bitrate tx, const m5::nfc::Bitrate rx)
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

uint32_t UnitST25R3916::readFIFO(uint16_t& actual, uint8_t* buf, const uint16_t buf_size)
{
    actual = 0;

    uint16_t bytes{};
    uint8_t bits{};
    if (readFIFOSize(bytes, bits)) {
        auto readSz = std::min<uint16_t>(bytes, buf_size);
        if (!readSz) {
            return false;
        }
        TRANSACTION_GUARD();
        if (!readRegister(OP_READ_FIFO, buf, readSz, 0, false)) {
            return false;
        }
        actual = readSz;
        return ((uint16_t)bits << 16) | bytes;
    }
    return 0u;
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
    return writeRegister(OP_LOAD_FIFO, buf, buf_size, true /*I2C, SPI not used*/);
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

bool UnitST25R3916::disableField()
{
    //////// >>>>>>>
    //    /* Set Analog configurations for Field Off event */
    //    rfalSetAnalogConfig((RFAL_ANALOG_CONFIG_TECH_CHIP | RFAL_ANALOG_CONFIG_CHIP_FIELD_OFF));

    return writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) &&
           modify_bit_register8(REG_OPERATION_CONTROL, 0x00, tx_en | rx_en);
}

bool UnitST25R3916::enableField()
{
    return writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) &&
           modify_bit_register8(REG_OPERATION_CONTROL, tx_en | rx_en, 0x00);
}

//
bool UnitST25R3916::read_register8(const uint8_t reg, uint8_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister8(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::read_register8(const uint16_t reg, uint8_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister8(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register8(const uint8_t reg, const uint8_t v)
{
    TRANSACTION_GUARD();
    return writeRegister8(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register8(const uint16_t reg, const uint8_t v)
{
    TRANSACTION_GUARD();
    return writeRegister8(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::read_register16(const uint8_t reg, uint16_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister16BE(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::read_register16(const uint16_t reg, uint16_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister16BE(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register16(const uint8_t reg, const uint16_t v)
{
    TRANSACTION_GUARD();
    return writeRegister16BE(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register16(const uint16_t reg, const uint16_t v)
{
    TRANSACTION_GUARD();
    return writeRegister16BE(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::read_register32(const uint8_t reg, uint32_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister32BE(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::read_register32(const uint16_t reg, uint32_t& v)
{
    TRANSACTION_GUARD();
    v = 0;
    return readRegister32BE(to_read_reg(reg), v, 0, false /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register32(const uint8_t reg, const uint32_t v)
{
    TRANSACTION_GUARD();
    return writeRegister32BE(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::write_register32(const uint16_t reg, const uint32_t v)
{
    TRANSACTION_GUARD();
    return writeRegister32BE(to_write_reg(reg), v, true /*I2C, SPI not used*/);
}

#if 0
uint32_t UnitST25R3916::wait_for_interrupt(const uint32_t irq, const uint32_t timeout_ms)
{
    auto timeout_at = m5::utility::millis() + timeout_ms;
    uint32_t flags{};
    do {
        if (!_using_irq || _interrupt_occurred) {
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
#else
uint32_t UnitST25R3916::wait_for_interrupt(const uint32_t bits, const uint32_t timeout_ms)
{
    auto timeout_at = m5::utility::millis() + timeout_ms;
    do {
        if (!_using_irq || _interrupt_occurred) {
            _interrupt_occurred = false;
            uint32_t v{};
            if (readInterrupts(v)) {
                _stored_irq = _stored_irq | v;
            }
        }
        uint32_t irq32 = _stored_irq & bits;
        if (irq32) {
            _stored_irq = _stored_irq & ~irq32;
            return irq32;
        }
        std::this_thread::yield();
    } while (m5::utility::millis() <= timeout_at);
    return _stored_irq | I_nre32;  // Timeout
}
#endif

bool UnitST25R3916::wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size)
{
    auto irq               = wait_for_interrupt(I_rxe32, timeout_ms);
    const uint16_t reqSize = required_size ? required_size : 1;

    if (is_irq32_rxe(irq)) {
        // M5_LIB_LOGE(" rxe OK IRQ:%08X", irq);
        return true;
    }
    // M5_LIB_LOGE("IRQ:%08X %u", irq, timeout_ms);

    // Check the FIFO size in case I_rxe doesn't arrive
    if (is_irq32_rxs(irq)) {
        auto timeout_at = m5::utility::millis() + timeout_ms;
        uint16_t bytes{};
        uint8_t bits{};
        do {
            if (readFIFOSize(bytes, bits) && bytes >= reqSize) {
                break;
            }
            std::this_thread::yield();
        } while (m5::utility::millis() <= timeout_at);
        // M5_LIB_LOGE("    FIFO:%u,%u/%u", bytes, bits, required_size);
        return readFIFOSize(bytes, bits) && bytes >= reqSize;
    }

    if (has_irq32_error(irq)) {
        M5_LIB_LOGE("Error: %08X", irq);
    }
    return false;
}

bool UnitST25R3916::write_fwt_timer(const uint32_t ms)
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

CapST25R3916::CapST25R3916(const uint8_t cs_pin) : UnitST25R3916(cs_pin)
{
    // HackerCap has IRQ PIN
    auto cfg      = config();
    cfg.using_irq = true;
    cfg.irq       = PIN_ST25R3916_IRQ;
    config(cfg);
}

bool CapST25R3916::begin()
{
    // Disbale ST25R3816
    pinMode(PIN_CS_ST25R3916, OUTPUT);
    digitalWrite(PIN_CS_ST25R3916, HIGH);

    return UnitST25R3916::begin();
}

}  // namespace unit
}  // namespace m5
