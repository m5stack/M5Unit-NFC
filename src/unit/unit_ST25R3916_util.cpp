/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_util.cpp
  @brief Utility API
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

#define TRANSACTION_GUARD() transaction_guard _tg_(adapter())

using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;

namespace m5 {
namespace unit {
namespace st25r3916 {

#if 0
uint16_t calculate_nrt(const uint32_t ms, const bool nrt_step)
{
    auto step_sec      = (nrt_step ? 4096 : 64) / 13560000.f;
    uint32_t nrt       = (uint32_t)std::round((ms / 1000.f) / step_sec);
    const uint32_t max = nrt_step ? 0xFFFF : 0xF857;
    if (nrt > max) {
        nrt = max;
    }
    // M5_LIB_LOGE(">>>> %ums fc4096:%u => %04X", ms, nrt_step, nrt);
    return nrt;
}

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
#endif

uint16_t calculate_nrt(const uint32_t ms, const bool nrt_step)
{
    constexpr uint32_t FC_HZ{13560000};
    constexpr uint64_t STEP64_NUM{64 * 1000000ul};
    constexpr uint64_t STEP4096_NUM{4096 * 1000000ul};
    const uint64_t step_num = nrt_step ? STEP4096_NUM : STEP64_NUM;

    uint64_t us  = (uint64_t)ms * 1000u;
    uint64_t nrt = (us * FC_HZ + step_num - 1) / step_num;
    return static_cast<uint16_t>(std::max<uint64_t>(std::min<uint64_t>(nrt, 0xFFFFu), 1u));
}

uint8_t calculate_mrt(const uint32_t us, const bool mrt_step /* false:64, true:512*/)
{
    constexpr uint32_t FC_HZ{13560000};
    constexpr uint32_t STEP64_NUM{64 * 1000000};
    constexpr uint32_t STEP512_NUM{512 * 1000000};
    const uint32_t step_num = mrt_step ? STEP512_NUM : STEP64_NUM;
    // mrt = ceil(us / step)
    uint32_t mrt = (us * FC_HZ + step_num - 1) / step_num;
    return static_cast<uint8_t>(std::max<uint32_t>(std::min<uint32_t>(mrt, 0xFFu), 4u));
}
}  // namespace st25r3916

bool UnitST25R3916::modify_bit_register8(const uint8_t reg, const uint8_t set_mask, const uint8_t clear_mask)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        const uint8_t w = (v & ~clear_mask) | set_mask;
        // M5_LIB_LOGE("[%2u]:%02X %02X/%02X => %02X %08o", reg, v, set_mask, clear_mask, w, OCB(w));
        if (w == v) {
            return true;
        }
        return write_register8(reg, w);
    }
    return false;
}

bool UnitST25R3916::modify_bit_register8(const uint16_t reg, const uint8_t set_mask, const uint8_t clear_mask)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        const uint8_t w = (v & ~clear_mask) | set_mask;
        // M5_LIB_LOGE("[%2u]:%02X %02X/%02X => %02X %08o", reg, v, set_mask, clear_mask, w, OCB(w));
        if (w == v) {
            return true;
        }
        return write_register8(reg, w);
    }
    return false;
}

bool UnitST25R3916::set_bit_register8(const uint8_t reg, const uint8_t bits)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        if (v == (v | bits)) {
            return true;
        }
        return write_register8(reg, v | bits);
    }
    return false;
}
bool UnitST25R3916::set_bit_register8(const uint16_t reg, const uint8_t bits)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        if (v == (v | bits)) {
            return true;
        }
        return write_register8(reg, v | bits);
    }
    return false;
}

bool UnitST25R3916::clear_bit_register8(const uint8_t reg, const uint8_t bits)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        if (v == (v & ~bits)) {
            return true;
        }
        return write_register8(reg, (v & ~bits));
    }
    return false;
}

bool UnitST25R3916::clear_bit_register8(const uint16_t reg, const uint8_t bits)
{
    uint8_t v{};
    if (read_register8(reg, v)) {
        if (v == (v & ~bits)) {
            return true;
        }
        return write_register8(reg, (v & ~bits));
    }
    return false;
}

bool UnitST25R3916::enable_interrupts(const uint32_t mask)
{
    if (writeMaskInterrupts(~mask)) {
        _mask_irq |= mask;
        return true;
    }
    return false;
}

bool UnitST25R3916::disable_interrupts(const uint32_t mask)
{
    if (writeMaskInterrupts(mask)) {
        _mask_irq &= ~mask;
        return true;
    }
    return false;
}

bool UnitST25R3916::enable_osc()
{
    uint8_t v{};
    if (!readOperationControl(v)) {
        M5_LIB_LOGE(">>>> ERR1");
        return false;
    }
    if ((v & en) == 0) {
        if (!modify_bit_register8(REG_MASK_MAIN_INTERRUPT, 0x00, I_osc) || !clearInterrupts()) {
            M5_LIB_LOGE(">>>> ERR2");
            return false;
        }
        set_bit_register8(REG_OPERATION_CONTROL, en);
        auto irq32 = wait_for_interrupt(I_osc, 10);  // about 700us
        modify_bit_register8(REG_MASK_MAIN_INTERRUPT, I_osc, 0x00);
        if ((irq32 & I_osc32) == 0) {
            M5_LIB_LOGE("IRQ:%08X", irq32);
            return false;
        }
    }
    return readAuxiliaryDisplay(v) && (v & osc_ok);
}

bool UnitST25R3916::disable_field()
{
    return writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) &&
           modify_bit_register8(REG_OPERATION_CONTROL, 0x00, rx_en | tx_en);
}

bool UnitST25R3916::writePtMemoryA(const uint8_t* tx, const uint32_t tx_len)
{
    if (!tx || !tx_len || tx_len > PT_MEMORY_A_LENGTH) {
        return false;
    }
    TRANSACTION_GUARD();
    return writeRegister(OP_LOAD_PT_MEMORY_A_CONFIG, tx, tx_len, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::writePtMemoryF(const uint8_t* tx, const uint32_t tx_len)
{
    if (!tx || !tx_len || tx_len > PT_MEMORY_F_LENGTH) {
        return false;
    }
    TRANSACTION_GUARD();
    return writeRegister(OP_LOAD_PT_MEMORY_F_CONFIG, tx, tx_len, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::writePtMemoryTSN(const uint8_t* tx, const uint32_t tx_len)
{
    if (!tx || !tx_len || tx_len > PT_MEMORY_TSN_LENGTH) {
        return false;
    }
    TRANSACTION_GUARD();
    return writeRegister(OP_LOAD_PT_MEMORY_TSN_DATA, tx, tx_len, true /*I2C, SPI not used*/);
}

bool UnitST25R3916::readPtMemory(uint8_t* rx, const uint32_t rx_len)
{
    if (!rx || !rx_len) {
        return false;
    }
    const uint32_t len = std::min<uint32_t>(rx_len, PT_MEMORY_LENGTH);

    TRANSACTION_GUARD();
    return readRegister(OP_READ_PT_MEMORY, rx, len, 0, false);
}

}  // namespace unit
}  // namespace m5
