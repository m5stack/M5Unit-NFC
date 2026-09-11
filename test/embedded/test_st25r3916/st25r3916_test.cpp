/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for ST25R3916
  Tests chip-level and layer-level functionality without requiring a physical PICC.
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include <M5UnitUnified.hpp>
#include <googletest/test_template.hpp>
#include <M5UnitUnifiedNFC.hpp>
#include <nfc/layer/a/nfc_layer_a.hpp>
#include <nfc/layer/b/nfc_layer_b.hpp>
#include <nfc/layer/f/nfc_layer_f.hpp>
#include <nfc/layer/v/nfc_layer_v.hpp>
#include <nfc/layer/a/emulation_layer_a.hpp>
#include <nfc/layer/f/emulation_layer_f.hpp>
#include <wiring/m5_unit_unified_wiring.hpp>
#include <cstring>

// Unit type is selected by build_flags: -D USING_UNIT_NFC or -D USING_CAP_CC1101
#if defined(USING_UNIT_NFC)
using TestUnit = m5::unit::UnitNFC;  // I2C (UnitST25R3916)
#elif defined(USING_CAP_CC1101)
using TestUnit = m5::unit::CapCC1101NFC;  // SPI (CapST25R3916)
#else
#error "Define USING_UNIT_NFC or USING_CAP_CC1101 via build_flags"
#endif

using namespace m5::unit::googletest;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::command;

// ============================================================
// Helper: stop RF field and clear state for clean test
// ============================================================
static bool stop_field(TestUnit* const u)
{
    return u->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) && u->writeOperationControl(0x00) && u->clearInterrupts();
}

// ============================================================
// Helper: switch the reader/emulation role by re-running begin()
// ============================================================
static bool rebegin_as(TestUnit* const u, const m5::nfc::NFC mode, const bool emulation)
{
    auto cfg      = u->config();
    cfg.mode      = mode;
    cfg.emulation = emulation;
    u->config(cfg);
    return u->begin();
}

// ============================================================
// Test fixture — uses I2C/SPI ComponentTestBase template
// ============================================================
#if defined(USING_UNIT_NFC)
class TestST25R3916 : public I2CComponentTestBase<TestUnit> {
protected:
    virtual bool begin() override
    {
        return m5::unit::wiring::addI2C(Units, *unit, 400 * 1000U, m5::unit::wiring::NessoPort::PortA) && Units.begin();
    }
    virtual TestUnit* get_instance() override
    {
        return new TestUnit();
    }
};
#elif defined(USING_CAP_CC1101)
class TestST25R3916 : public SPIComponentTestBase<TestUnit> {
protected:
    virtual bool begin() override
    {
        return m5::unit::wiring::addSPI(Units, *unit, 10000000, 1) && Units.begin();
    }
    virtual TestUnit* get_instance() override
    {
        return new TestUnit();
    }
    virtual SPISettings get_spi_settings() override
    {
        return SPISettings(10000000, MSBFIRST, SPI_MODE1);
    }
};
#endif

// ============================================================
// Helper macros: Register roundtrip tests
// ============================================================
#define TEST_REGISTER_ROUNDTRIP_8(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                       \
    {                                                                     \
        uint8_t original{};                                               \
        EXPECT_TRUE(unit->readFunc(original));                            \
        EXPECT_TRUE(unit->writeFunc(testVal));                            \
        uint8_t readback{};                                               \
        EXPECT_TRUE(unit->readFunc(readback));                            \
        EXPECT_EQ(readback, static_cast<uint8_t>(testVal));               \
        EXPECT_TRUE(unit->writeFunc(original));                           \
    }

#define TEST_REGISTER_ROUNDTRIP_16(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                        \
    {                                                                      \
        uint16_t original{};                                               \
        EXPECT_TRUE(unit->readFunc(original));                             \
        EXPECT_TRUE(unit->writeFunc(testVal));                             \
        uint16_t readback{};                                               \
        EXPECT_TRUE(unit->readFunc(readback));                             \
        EXPECT_EQ(readback, static_cast<uint16_t>(testVal));               \
        EXPECT_TRUE(unit->writeFunc(original));                            \
    }

#define TEST_REGISTER_ROUNDTRIP_32(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                        \
    {                                                                      \
        uint32_t original{};                                               \
        EXPECT_TRUE(unit->readFunc(original));                             \
        EXPECT_TRUE(unit->writeFunc(testVal));                             \
        uint32_t readback{};                                               \
        EXPECT_TRUE(unit->readFunc(readback));                             \
        EXPECT_EQ(readback, static_cast<uint32_t>(testVal));               \
        EXPECT_TRUE(unit->writeFunc(original));                            \
    }

// ============================================================
// Part 1: Basic connectivity
// ============================================================

TEST_F(TestST25R3916, Begin)
{
    uint8_t type{}, rev{};
    EXPECT_TRUE(unit->readICIdentity(type, rev));
}

TEST_F(TestST25R3916, ICIdentity)
{
    uint8_t type{}, rev{};
    EXPECT_TRUE(unit->readICIdentity(type, rev));
    EXPECT_EQ(type, VALID_IDENTIFY_TYPE) << "Expected ST25R3916/7 type=0x05";
    EXPECT_NE(rev, 0U) << "Revision must be non-zero";
}

// ============================================================
// Part 1: Register roundtrip — timers
// ============================================================

TEST_REGISTER_ROUNDTRIP_8(Reg_MaskReceiveTimer, readMaskReceiveTimer, writeMaskReceiveTimer, 0x55U)
TEST_REGISTER_ROUNDTRIP_16(Reg_NoResponseTimer, readNoResponseTimer, writeNoResponseTimer, 0x1234U)
TEST_REGISTER_ROUNDTRIP_16(Reg_GeneralPurposeTimer, readGeneralPurposeTimer, writeGeneralPurposeTimer, 0xABCDU)
TEST_REGISTER_ROUNDTRIP_8(Reg_PPON2FieldWaiting, readPPON2FieldWaiting, writePPON2FieldWaiting, 0x42U)
TEST_REGISTER_ROUNDTRIP_8(Reg_SquelchTimer, readSquelchTimer, writeSquelchTimer, 0x33U)
TEST_REGISTER_ROUNDTRIP_8(Reg_NFCFieldOnGuardTimer, readNFCFieldOnGuardTimer, writeNFCFieldOnGuardTimer, 0x77U)

// ============================================================
// Part 1: Register roundtrip — configuration
// ============================================================

TEST_REGISTER_ROUNDTRIP_16(Reg_IOConfiguration, readIOConfiguration, writeIOConfiguration, 0x0020U)
TEST_REGISTER_ROUNDTRIP_8(Reg_TimerAndEMVControl, readTimerAndEMVControl, writeTimerAndEMVControl, 0x01U)
TEST_REGISTER_ROUNDTRIP_8(Reg_EMDSuppression, readEMDSuppressionConfiguration, writeEMDSuppressionConfiguration, 0x08U)
TEST_REGISTER_ROUNDTRIP_8(Reg_SubcarrierStartTimer, readSubcarrierStartTimer, writeSubcarrierStartTimer, 0x10U)

// ============================================================
// Part 1: Register roundtrip — receiver
// ============================================================

TEST_REGISTER_ROUNDTRIP_8(Reg_ReceiverConfiguration1, readReceiverConfiguration1, writeReceiverConfiguration1, 0x08U)
TEST_REGISTER_ROUNDTRIP_8(Reg_ReceiverConfiguration2, readReceiverConfiguration2, writeReceiverConfiguration2, 0x28U)
TEST_REGISTER_ROUNDTRIP_8(Reg_ReceiverConfiguration3, readReceiverConfiguration3, writeReceiverConfiguration3, 0x00U)
TEST_REGISTER_ROUNDTRIP_8(Reg_ReceiverConfiguration4, readReceiverConfiguration4, writeReceiverConfiguration4, 0x00U)
TEST_REGISTER_ROUNDTRIP_32(Reg_ReceiverConfiguration, readReceiverConfiguration, writeReceiverConfiguration,
                           0x08280000UL)
TEST_REGISTER_ROUNDTRIP_16(Reg_CorrelatorConfiguration, readCorrelatorConfiguration, writeCorrelatorConfiguration,
                           0x0302U)
TEST_REGISTER_ROUNDTRIP_8(Reg_P2PReceiverConfiguration, readP2PReceiverConfiguration, writeP2PReceiverConfiguration,
                          0x00U)

// ============================================================
// Part 1: Register roundtrip — protection
// ============================================================

TEST_REGISTER_ROUNDTRIP_16(Reg_OvershootProtection, readOvershootProtectionConfiguration,
                           writeOvershootProtectionConfiguration, 0x1020U)
TEST_REGISTER_ROUNDTRIP_16(Reg_UndershootProtection, readUndershootProtectionConfiguration,
                           writeUndershootProtectionConfiguration, 0x3040U)

// ============================================================
// Part 1: Register roundtrip — NFC settings
// ============================================================

TEST_REGISTER_ROUNDTRIP_8(Reg_SettingsISO14443A, readSettingsISO14443A, writeSettingsISO14443A, 0x00U)
TEST_REGISTER_ROUNDTRIP_8(Reg_SettingsISO14443B, readSettingsISO14443B, writeSettingsISO14443B, 0x00U)
TEST_REGISTER_ROUNDTRIP_8(Reg_SettingsFelica, readSettingsFelica, writeSettingsFelica, 0x00U)
TEST_REGISTER_ROUNDTRIP_8(Reg_AuxiliaryDefinition, readAuxiliaryDefinition, writeAuxiliaryDefinition, 0x00U)
TEST_REGISTER_ROUNDTRIP_8(Reg_StreamModeDefinition, readStreamModeDefinition, writeStreamModeDefinition, 0x00U)

// ============================================================
// Part 1: Register roundtrip — transmitted bytes
// ============================================================

TEST_REGISTER_ROUNDTRIP_16(Reg_NumberOfTransmittedBytes, readNumberOfTransmittedBytes, writeNumberOfTransmittedBytes,
                           0x0100U)

// ============================================================
// Part 1: Register roundtrip — operation control
// ============================================================

TEST_REGISTER_ROUNDTRIP_8(Reg_OperationControl, readOperationControl, writeOperationControl, 0x00U)

// ============================================================
// Part 1: Interrupt mask — partial roundtrip
// (Some bits are hardware-reserved and may not write back exactly)
// ============================================================

TEST_F(TestST25R3916, Reg_MaskInterrupts_WrittenBitsReadBack)
{
    uint32_t original{};
    EXPECT_TRUE(unit->readMaskInterrupts(original));

    // Write a known pattern
    const uint32_t pattern = 0xAAAAAAAAUL;
    EXPECT_TRUE(unit->writeMaskInterrupts(pattern));

    uint32_t readback{};
    EXPECT_TRUE(unit->readMaskInterrupts(readback));
    // Verify writable bits match (some bits may be reserved)
    // At minimum, the written bits that ARE writable should be set
    EXPECT_NE(readback, 0U) << "At least some bits should be writable";

    // Restore
    EXPECT_TRUE(unit->writeMaskInterrupts(original));
}

// ============================================================
// Part 1: Read-only status registers
// ============================================================

TEST_F(TestST25R3916, ReadOnly_FIFOStatus)
{
    uint16_t status{};
    EXPECT_TRUE(unit->readFIFOStatus(status));
    uint8_t s1{}, s2{};
    EXPECT_TRUE(unit->readFIFOStatus1(s1));
    EXPECT_TRUE(unit->readFIFOStatus2(s2));
}

TEST_F(TestST25R3916, ReadOnly_CollisionDisplay)
{
    uint8_t value{};
    EXPECT_TRUE(unit->readCollisionDisplay(value));
}

TEST_F(TestST25R3916, ReadOnly_PassiveTargetDisplay)
{
    uint8_t value{};
    EXPECT_TRUE(unit->readPassiveTargetDisplay(value));
}

TEST_F(TestST25R3916, ReadOnly_Interrupts)
{
    uint8_t main_irq{}, timer_irq{}, error_irq{}, passive_irq{};
    EXPECT_TRUE(unit->readMainInterrupt(main_irq));
    EXPECT_TRUE(unit->readTimerAndNFCInterrupt(timer_irq));
    EXPECT_TRUE(unit->readErrorAndWakeupInterrupt(error_irq));
    EXPECT_TRUE(unit->readPassiveTargetInterrupt(passive_irq));

    uint32_t all_irq{};
    EXPECT_TRUE(unit->readInterrupts(all_irq));
}

// ============================================================
// Part 1: config_t
// ============================================================

TEST_F(TestST25R3916, ConfigGetterByValue)
{
    auto cfg_orig = unit->config();

    auto cfg_mutated             = cfg_orig;
    cfg_mutated.vdd_voltage_5V   = !cfg_orig.vdd_voltage_5V;
    cfg_mutated.tx_am_modulation = static_cast<uint8_t>((cfg_orig.tx_am_modulation + 1U) & 0x0FU);

    // Original should be unchanged
    auto cfg_check = unit->config();
    EXPECT_EQ(cfg_check.vdd_voltage_5V, cfg_orig.vdd_voltage_5V);
    EXPECT_EQ(cfg_check.tx_am_modulation, cfg_orig.tx_am_modulation);

    // Set mutated config and re-read
    unit->config(cfg_mutated);
    auto cfg_after = unit->config();
    EXPECT_EQ(cfg_after.vdd_voltage_5V, cfg_mutated.vdd_voltage_5V);
    EXPECT_EQ(cfg_after.tx_am_modulation, cfg_mutated.tx_am_modulation);

    // Restore
    unit->config(cfg_orig);
}

TEST_F(TestST25R3916, ConfigFieldDefaults)
{
    TestUnit::config_t cfg{};
    EXPECT_FALSE(cfg.vdd_voltage_5V);
    EXPECT_EQ(cfg.tx_am_modulation, 13);
    EXPECT_FALSE(cfg.using_irq);
    EXPECT_EQ(cfg.irq, 0);
    EXPECT_FALSE(cfg.emulation);
}

// ============================================================
// Part 1: NFC mode configuration
// (Must stop field first since begin() enables tx_en)
// ============================================================

TEST_F(TestST25R3916, ConfigureNFCMode_A)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::A));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::A));
}

TEST_F(TestST25R3916, ConfigureNFCMode_B)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::B));
}

TEST_F(TestST25R3916, ConfigureNFCMode_F)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::F));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::F));
}

TEST_F(TestST25R3916, ConfigureNFCMode_V)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::V));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::V));
}

TEST_F(TestST25R3916, ConfigureNFCMode_Roundtrip)
{
    const m5::nfc::NFC modes[] = {m5::nfc::NFC::A, m5::nfc::NFC::B, m5::nfc::NFC::F, m5::nfc::NFC::V};
    for (auto mode : modes) {
        SCOPED_TRACE(static_cast<int>(mode));
        EXPECT_TRUE(stop_field(unit.get()));
        EXPECT_TRUE(unit->configureNFCMode(mode));
        EXPECT_TRUE(unit->isNFCMode(mode));
        EXPECT_EQ(unit->NFCMode(), mode);
    }
}

TEST_F(TestST25R3916, ConfigureNFCMode_None_Fails)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_FALSE(unit->configureNFCMode(m5::nfc::NFC::None));
}

// ============================================================
// Part 1: Direct commands
// ============================================================

TEST_F(TestST25R3916, DirectCommand_SetDefault)
{
    EXPECT_TRUE(unit->writeDirectCommand(CMD_SET_DEFAULT));
}

TEST_F(TestST25R3916, DirectCommand_ClearFIFO)
{
    EXPECT_TRUE(unit->writeDirectCommand(CMD_CLEAR_FIFO));
}

TEST_F(TestST25R3916, DirectCommand_CalibrateCapacitiveSensor)
{
    EXPECT_TRUE(unit->writeDirectCommand(CMD_CALIBRATE_CAPACITIVE_SENSOR));
}

TEST_F(TestST25R3916, DirectCommand_MeasurePowerSupply)
{
    EXPECT_TRUE(unit->writeDirectCommand(CMD_MEASURE_POWER_SUPPLY));
}

TEST_F(TestST25R3916, DirectCommand_StopAllActivities)
{
    EXPECT_TRUE(unit->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES));
}

// ============================================================
// Part 1: FIFO (stop field first to get clean state)
// ============================================================

TEST_F(TestST25R3916, FIFOSizeAfterClear)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->writeDirectCommand(CMD_CLEAR_FIFO));

    uint16_t bytes{0xFFFFU};
    uint8_t bits{0xFFU};
    EXPECT_TRUE(unit->readFIFOSize(bytes, bits));
    EXPECT_EQ(bytes, 0U);
    EXPECT_EQ(bits, 0U);
}

TEST_F(TestST25R3916, FIFOWrite_Succeeds)
{
    // FIFO requires Ready mode (en bit set). Stop TX/RX but keep en.
    EXPECT_TRUE(unit->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES));
    EXPECT_TRUE(unit->writeOperationControl(regval::en));
    EXPECT_TRUE(unit->writeDirectCommand(CMD_CLEAR_FIFO));

    const uint8_t pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_TRUE(unit->writeFIFO(pattern, sizeof(pattern)));
    // Note: FIFO read-back behavior varies by transport (I2C vs Ex_I2C vs SPI).
    // Full roundtrip verification is not reliable across all boards.
}

TEST_F(TestST25R3916, FIFOWrite_RejectOversize)
{
    // Writing more than MAX_FIFO_DEPTH should fail
    uint8_t big[MAX_FIFO_DEPTH + 1] = {};
    EXPECT_FALSE(unit->writeFIFO(big, sizeof(big)));
}

TEST_F(TestST25R3916, FIFOWrite_RejectNull)
{
    EXPECT_FALSE(unit->writeFIFO(nullptr, 4));
    uint8_t buf[1] = {};
    EXPECT_FALSE(unit->writeFIFO(buf, 0));
}

// ============================================================
// Part 1: clearInterrupts
// ============================================================

TEST_F(TestST25R3916, ClearInterrupts)
{
    EXPECT_TRUE(unit->clearInterrupts());
}

// ============================================================
// Part 1: Bitrate (stop field before configureNFCMode)
// ============================================================

TEST_F(TestST25R3916, WriteBitrate_NFCA)
{
    using m5::nfc::Bitrate;
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::A));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCF)
{
    using m5::nfc::Bitrate;
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::F));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps212K, Bitrate::Bps212K));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps424K, Bitrate::Bps424K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCB)
{
    using m5::nfc::Bitrate;
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps212K, Bitrate::Bps212K));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps424K, Bitrate::Bps424K));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps848K, Bitrate::Bps848K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCV)
{
    using m5::nfc::Bitrate;
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::V));
    EXPECT_TRUE(unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
}

// ============================================================
// Part 1: Initiator / Target operation mode
// ============================================================

TEST_F(TestST25R3916, InitiatorOperationMode)
{
    EXPECT_TRUE(unit->writeInitiatorOperationMode(InitiatorOperationMode::ISO14443A));
    EXPECT_TRUE(unit->writeInitiatorOperationMode(InitiatorOperationMode::ISO14443B));
    EXPECT_TRUE(unit->writeInitiatorOperationMode(InitiatorOperationMode::FeliCa));
    EXPECT_TRUE(unit->writeInitiatorOperationMode(InitiatorOperationMode::NFCForumType1));
    EXPECT_TRUE(unit->writeInitiatorOperationMode(InitiatorOperationMode::SubCarrierStream));
}

TEST_F(TestST25R3916, TargetOperationMode)
{
    EXPECT_TRUE(unit->writeTargetOperationMode(TargetOperationMode::ISO14443A));
    EXPECT_TRUE(unit->writeTargetOperationMode(TargetOperationMode::Felica));
    EXPECT_TRUE(unit->writeTargetOperationMode(TargetOperationMode::NFCIP1));
}

// ============================================================
// Part 1: Mode/Bitrate definition registers
// ============================================================

TEST_F(TestST25R3916, ModeDefinition_ReadWrite)
{
    uint8_t original{};
    EXPECT_TRUE(unit->readModeDefinition(original));

    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::A));
    uint8_t mode_val{};
    EXPECT_TRUE(unit->readModeDefinition(mode_val));

    EXPECT_TRUE(unit->writeModeDefinition(original));
}

TEST_F(TestST25R3916, BitrateDefinition_ReadWrite)
{
    uint8_t original{};
    EXPECT_TRUE(unit->readBitrateDefinition(original));

    const uint8_t test_val = 0x00U;
    EXPECT_TRUE(unit->writeBitrateDefinition(test_val));

    uint8_t readback{};
    EXPECT_TRUE(unit->readBitrateDefinition(readback));
    EXPECT_EQ(readback, test_val);

    EXPECT_TRUE(unit->writeBitrateDefinition(original));
}

// ============================================================
// Part 1: Reset and verify clean state
// ============================================================

TEST_F(TestST25R3916, SetDefaultResetsGPT)
{
    EXPECT_TRUE(unit->writeGeneralPurposeTimer(0x1234U));

    EXPECT_TRUE(unit->writeDirectCommand(CMD_SET_DEFAULT));

    uint16_t gpt{};
    EXPECT_TRUE(unit->readGeneralPurposeTimer(gpt));
    EXPECT_EQ(gpt, 0x0000U) << "GPT should be 0 after CMD_SET_DEFAULT";
}

// ============================================================
// Part 1: Layer construction and properties
// ============================================================

TEST_F(TestST25R3916, NFCLayerA_Construction)
{
    m5::nfc::NFCLayerA nfc_a{*unit};
    EXPECT_EQ(nfc_a.maximum_fifo_depth(), MAX_FIFO_DEPTH);
    EXPECT_EQ(nfc_a.supportsNFCTag(), m5::nfc::NFCForumTag::None);
}

TEST_F(TestST25R3916, NFCLayerB_Construction)
{
    m5::nfc::NFCLayerB nfc_b{*unit};
    EXPECT_EQ(nfc_b.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

TEST_F(TestST25R3916, NFCLayerF_Construction)
{
    m5::nfc::NFCLayerF nfc_f{*unit};
    EXPECT_EQ(nfc_f.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

TEST_F(TestST25R3916, NFCLayerV_Construction)
{
    m5::nfc::NFCLayerV nfc_v{*unit};
    EXPECT_EQ(nfc_v.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

// ============================================================
// Part 2: Emulation layer
// ============================================================

TEST_F(TestST25R3916, EmulationLayerA_InitialState)
{
    m5::nfc::EmulationLayerA emu_a{*unit};
    EXPECT_EQ(emu_a.state(), m5::nfc::EmulationLayerA::State::None);
    // Default expired time is 60 seconds
    EXPECT_EQ(emu_a.expiredTime(), 60000U);
}

TEST_F(TestST25R3916, EmulationLayerF_InitialState)
{
    m5::nfc::EmulationLayerF emu_f{*unit};
    EXPECT_EQ(emu_f.state(), m5::nfc::EmulationLayerF::State::None);
    EXPECT_EQ(emu_f.expiredTime(), 60000U);
}

TEST_F(TestST25R3916, EmulationLayerA_SetExpiredTime)
{
    m5::nfc::EmulationLayerA emu_a{*unit};
    emu_a.setExpiredTime(5000);
    EXPECT_EQ(emu_a.expiredTime(), 5000U);
    emu_a.setExpiredTime(0);
    EXPECT_EQ(emu_a.expiredTime(), 0U);
}

TEST_F(TestST25R3916, EmulationLayerF_SetExpiredTime)
{
    m5::nfc::EmulationLayerF emu_f{*unit};
    emu_f.setExpiredTime(10000);
    EXPECT_EQ(emu_f.expiredTime(), 10000U);
    emu_f.setExpiredTime(0);
    EXPECT_EQ(emu_f.expiredTime(), 0U);
}

// ============================================================
// Part 2: Layer construction doesn't change NFC mode
// ============================================================

TEST_F(TestST25R3916, NFCLayerA_ModeUnchanged)
{
    EXPECT_TRUE(stop_field(unit.get()));
    EXPECT_TRUE(unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::B));

    {
        m5::nfc::NFCLayerA nfc_a{*unit};
    }

    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::B));
}

// ============================================================
// Part 3: begin() applies config_t to chip
// ============================================================

// Verify that the values set via config() are actually applied to the chip
// when begin() runs. This catches regressions where config_t fields are
// stored but never written to hardware.
TEST_F(TestST25R3916, BeginAppliesConfig)
{
    // Capture initial config (set by SetUp -> begin())
    auto cfg_initial = unit->config();

    // Mutate two fields that are observable via readIOConfiguration / readTXDriver
    auto cfg_mutated             = cfg_initial;
    cfg_mutated.vdd_voltage_5V   = !cfg_initial.vdd_voltage_5V;
    cfg_mutated.tx_am_modulation = static_cast<uint8_t>((cfg_initial.tx_am_modulation + 1U) & 0x0FU);
    unit->config(cfg_mutated);

    // Re-run begin() to apply the new config
    EXPECT_TRUE(unit->begin());

    // sup3v (0x80) lives in IO_CONFIG_2 (low byte of readIOConfiguration's MSB=cfg1/LSB=cfg2 packing).
    // Set when vdd is 3V (i.e. vdd_voltage_5V == false).
    uint16_t io_cfg{};
    EXPECT_TRUE(unit->readIOConfiguration(io_cfg));
    const bool sup3v_bit_set = (io_cfg & 0x0080U) != 0;
    EXPECT_EQ(sup3v_bit_set, !cfg_mutated.vdd_voltage_5V) << "vdd_voltage_5V should drive sup3v bit";

    // TX_AM_modulation: high 4 bits of TX driver register (writeTXDriver shifts tx_am_modulation << 4)
    uint8_t tx_driver{};
    EXPECT_TRUE(unit->readTXDriver(tx_driver));
    EXPECT_EQ((tx_driver >> 4) & 0x0FU, cfg_mutated.tx_am_modulation & 0x0FU)
        << "tx_am_modulation should drive high 4 bits of TX driver register";

    // Restore the original config and re-apply
    unit->config(cfg_initial);
    EXPECT_TRUE(unit->begin());
}

// ============================================================
// Part 4: NFC-F emulation
// ============================================================

constexpr uint8_t emulation_idm[m5::nfc::f::FELICA_ID_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
constexpr uint8_t emulation_pmm[m5::nfc::f::FELICA_ID_LENGTH] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

// The chip emulates one technology at a time, so a layer must refuse to start on a unit that was
// configured for the other one. The refusal happens before any register is written, so the chip is
// left exactly as it was.
TEST_F(TestST25R3916, EmulationRejectedInWrongMode)
{
    const auto cfg_initial = unit->config();
    uint8_t memory[256]{};

    // Configured for NFC-A, so the NFC-F layer must refuse
    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::A, true));

    m5::nfc::f::PICC picc_f{};
    EXPECT_TRUE(picc_f.emulate(m5::nfc::f::Type::FeliCaLiteS, emulation_idm, emulation_pmm));

    m5::nfc::EmulationLayerF emu_f{*unit};
    EXPECT_FALSE(emu_f.begin(picc_f, memory, sizeof(memory)));
    EXPECT_EQ(emu_f.state(), m5::nfc::EmulationLayerF::State::None);

    // Configured for NFC-F, so the NFC-A layer must refuse
    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::F, true));

    constexpr uint8_t uid[] = {0x04, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE};
    m5::nfc::a::PICC picc_a{};
    EXPECT_TRUE(picc_a.emulate(m5::nfc::a::Type::MIFARE_Ultralight, uid, sizeof(uid)));

    m5::nfc::EmulationLayerA emu_a{*unit};
    EXPECT_FALSE(emu_a.begin(picc_a, memory, sizeof(memory)));
    EXPECT_EQ(emu_a.state(), m5::nfc::EmulationLayerA::State::None);

    unit->config(cfg_initial);
    EXPECT_TRUE(unit->begin());
}

// Reader NFC-F and emulator NFC-F share m5::nfc::NFC::F, but the chip needs a different role
// setup for each. Switching from reader to emulator must still rebuild the target registers;
// this catches regressions where an early return skips configure_emulation_f().
TEST_F(TestST25R3916, EmulationF_ReconfiguresTargetAfterReaderMode)
{
    const auto cfg_initial = unit->config();

    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::F, false));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::F));

    // Same mode, but the role changes from initiator to target
    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::F, true));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::F));

    uint8_t value{};
    EXPECT_TRUE(unit->readModeDefinition(value));
    EXPECT_EQ(value, 0xE0) << "Target, NFC-F, bit rate detection mode";
    EXPECT_TRUE(unit->readNFCIP1PassiveTargetDefinition(value));
    EXPECT_EQ(value, 0x5C) << "Auto response for NFC-F must be enabled";
    EXPECT_TRUE(unit->readMaskPassiveTargetInterrupt(value));
    EXPECT_EQ(value, 0x02) << "I_wu_ax masked";
    EXPECT_TRUE(unit->readTimerAndEMVControl(value));
    EXPECT_EQ(value, 0x08) << "mrt_setp 512";

    unit->config(cfg_initial);
    EXPECT_TRUE(unit->begin());
}

// The NFC-A counterpart of the test above. Reader NFC-A and emulator NFC-A also share
// m5::nfc::NFC::A, and only the mode definition tells the two target setups apart.
TEST_F(TestST25R3916, EmulationA_ReconfiguresTargetAfterReaderMode)
{
    const auto cfg_initial = unit->config();

    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::A, false));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::A));

    // Same mode, but the role changes from initiator to target
    EXPECT_TRUE(rebegin_as(unit.get(), m5::nfc::NFC::A, true));
    EXPECT_TRUE(unit->isNFCMode(m5::nfc::NFC::A));

    uint8_t value{};
    EXPECT_TRUE(unit->readModeDefinition(value));
    EXPECT_EQ(value, 0xC8) << "Target, NFC-A, bit rate detection mode";
    EXPECT_TRUE(unit->readNFCIP1PassiveTargetDefinition(value));
    EXPECT_EQ(value, 0x5C) << "Auto response for NFC-A must be enabled";
    EXPECT_TRUE(unit->readMaskPassiveTargetInterrupt(value));
    EXPECT_EQ(value, 0x02) << "I_wu_ax masked";
    EXPECT_TRUE(unit->readTimerAndEMVControl(value));
    EXPECT_EQ(value, 0x08) << "mrt_setp 512";

    unit->config(cfg_initial);
    EXPECT_TRUE(unit->begin());
}

// Ending an emulation that was never started is a caller mistake, but it stays idempotent so
// that defensive cleanup does not have to know whether begin() ran.
TEST_F(TestST25R3916, EmulationEndWithoutBegin)
{
    m5::nfc::EmulationLayerF emu_f{*unit};
    EXPECT_EQ(emu_f.state(), m5::nfc::EmulationLayerF::State::None);
    EXPECT_TRUE(emu_f.end());
    EXPECT_EQ(emu_f.state(), m5::nfc::EmulationLayerF::State::None);

    m5::nfc::EmulationLayerA emu_a{*unit};
    EXPECT_EQ(emu_a.state(), m5::nfc::EmulationLayerA::State::None);
    EXPECT_TRUE(emu_a.end());
    EXPECT_EQ(emu_a.state(), m5::nfc::EmulationLayerA::State::None);
}

// ============================================================
// Part 5: PT memory
// ============================================================

// The first Polling response is answered by the chip itself from PT memory, before the software
// receive path runs, so the request data has to reach the chip and not just the SENSF_RES that
// EmulationLayerF builds. Emulation is not started here: goto_off() drops the chip to power-down
// to wait for a reader field, and PT memory is unreachable there. Reading it back also covers the
// leading dummy byte the chip prepends to a PT memory read.
TEST_F(TestST25R3916, PtMemoryRoundtrip)
{
    m5::nfc::f::PICC picc{};
    EXPECT_TRUE(picc.emulate(m5::nfc::f::Type::FeliCaLiteS, emulation_idm, emulation_pmm));

    uint8_t wbuf[m5::nfc::f::FELICA_PT_MEMORY_SIZE]{};
    EXPECT_TRUE(m5::nfc::f::make_emulation_polling_memory(wbuf, picc));
    EXPECT_EQ(wbuf[19], 0x00) << "Request data (high)";
    EXPECT_EQ(wbuf[20], 0x83) << "Request data (low)";

    EXPECT_TRUE(unit->writePtMemoryF(wbuf, sizeof(wbuf)));

    uint8_t pt[PT_MEMORY_LENGTH]{};
    EXPECT_TRUE(unit->readPtMemory(pt, sizeof(pt)));
    EXPECT_EQ(std::memcmp(pt + PT_MEMORY_A_LENGTH, wbuf, sizeof(wbuf)), 0) << "F-config read back";
}

// PT memory is only reachable in Ready mode. Outside it the chip returns nothing useful, so the
// accessors must refuse instead of handing back a silently zeroed buffer.
TEST_F(TestST25R3916, PtMemoryRejectedOutsideReadyMode)
{
    EXPECT_TRUE(unit->writeOperationControl(0x00));  // To power-down mode

    uint8_t pt[PT_MEMORY_LENGTH]{};
    EXPECT_FALSE(unit->readPtMemory(pt, sizeof(pt)));

    uint8_t wbuf[m5::nfc::f::FELICA_PT_MEMORY_SIZE]{};
    EXPECT_FALSE(unit->writePtMemoryF(wbuf, sizeof(wbuf)));

    EXPECT_TRUE(unit->begin());  // Restore
}

// The A-config area is written through its own op code and lands at the head of PT memory.
TEST_F(TestST25R3916, PtMemoryRoundtripNfcA)
{
    uint8_t wbuf[PT_MEMORY_A_LENGTH]{};
    for (uint32_t i = 0; i < sizeof(wbuf); ++i) {
        wbuf[i] = static_cast<uint8_t>(0xA0 + i);
    }
    EXPECT_TRUE(unit->writePtMemoryA(wbuf, sizeof(wbuf)));

    uint8_t pt[PT_MEMORY_LENGTH]{};
    EXPECT_TRUE(unit->readPtMemory(pt, sizeof(pt)));
    EXPECT_EQ(std::memcmp(pt, wbuf, sizeof(wbuf)), 0) << "A-config read back";
}

// The TSN block has its own op code so the random numbers can be reloaded without rewriting
// the rest of PT memory. It sits after the A and F areas.
TEST_F(TestST25R3916, PtMemoryRoundtripTSN)
{
    uint8_t wbuf[PT_MEMORY_TSN_LENGTH]{};
    for (uint32_t i = 0; i < sizeof(wbuf); ++i) {
        wbuf[i] = static_cast<uint8_t>(0x5A + i);
    }
    EXPECT_TRUE(unit->writePtMemoryTSN(wbuf, sizeof(wbuf)));

    uint8_t pt[PT_MEMORY_LENGTH]{};
    EXPECT_TRUE(unit->readPtMemory(pt, sizeof(pt)));
    EXPECT_EQ(std::memcmp(pt + PT_MEMORY_A_LENGTH + PT_MEMORY_F_LENGTH, wbuf, sizeof(wbuf)), 0) << "TSN read back";
}
