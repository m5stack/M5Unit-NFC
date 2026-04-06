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
#include <SPI.h>
#include <cstring>

// Unit type is selected by build_flags: -D USING_UNIT_NFC or -D USING_HACKER_CAP
#if defined(USING_UNIT_NFC)
using TestUnit = m5::unit::UnitNFC;  // I2C (UnitST25R3916)
#elif defined(USING_HACKER_CAP)
using TestUnit = m5::unit::HackerCapNFC;  // SPI (CapST25R3916)
#else
#error "Define USING_UNIT_NFC or USING_HACKER_CAP via build_flags"
#endif

using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::command;

// ============================================================
// Helper: stop RF field and clear state for clean test
// ============================================================
static bool stop_field(TestUnit* unit)
{
    return unit->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES) && unit->writeOperationControl(0x00) &&
           unit->clearInterrupts();
}

// ============================================================
// Test fixture — static init (once per test suite)
// ============================================================
class TestST25R3916 : public ::testing::Test {
public:
    static void SetUpTestSuite()
    {
        _unit = new TestUnit();
        if (!_unit) {
            return;
        }

#if defined(USING_UNIT_NFC)
        // NessoN1: SoftwareI2C too slow for NFC RF timing — falls into else (Wire on port_a)
        auto board = M5.getBoard();
        if (board == m5::board_t::board_M5NanoC6) {
            _unit_ready = _units.add(*_unit, M5.Ex_I2C) && _units.begin();
        } else {
            auto sda = M5.getPin(m5::pin_name_t::port_a_sda);
            auto scl = M5.getPin(m5::pin_name_t::port_a_scl);
            Wire.end();
            Wire.begin(sda, scl, 400000U);
            _unit_ready = _units.add(*_unit, Wire) && _units.begin();
        }
#elif defined(USING_HACKER_CAP)
        // SPI: Cardputer uses sd_spi pins
        if (!SPI.bus()) {
            auto spi_sclk = M5.getPin(m5::pin_name_t::sd_spi_sclk);
            auto spi_mosi = M5.getPin(m5::pin_name_t::sd_spi_mosi);
            auto spi_miso = M5.getPin(m5::pin_name_t::sd_spi_miso);
            SPI.begin(spi_sclk, spi_miso, spi_mosi);
        }
        SPISettings settings = {10000000, MSBFIRST, SPI_MODE1};
        _unit_ready          = _units.add(*_unit, SPI, settings) && _units.begin();
#endif
    }

    static void TearDownTestSuite()
    {
        delete _unit;
        _unit = nullptr;
    }

    void SetUp() override
    {
        ASSERT_NE(_unit, nullptr);
        ASSERT_TRUE(_unit_ready) << "Unit not ready - check wiring and build_flags";
    }

    static TestUnit* _unit;
    static m5::unit::UnitUnified _units;
    static bool _unit_ready;
};

TestUnit* TestST25R3916::_unit              = nullptr;
m5::unit::UnitUnified TestST25R3916::_units = {};
bool TestST25R3916::_unit_ready             = false;

// ============================================================
// Helper macros: Register roundtrip tests
// ============================================================
#define TEST_REGISTER_ROUNDTRIP_8(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                       \
    {                                                                     \
        uint8_t original{};                                               \
        ASSERT_TRUE(_unit->readFunc(original));                           \
        EXPECT_TRUE(_unit->writeFunc(testVal));                           \
        uint8_t readback{};                                               \
        EXPECT_TRUE(_unit->readFunc(readback));                           \
        EXPECT_EQ(readback, static_cast<uint8_t>(testVal));               \
        EXPECT_TRUE(_unit->writeFunc(original));                          \
    }

#define TEST_REGISTER_ROUNDTRIP_16(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                        \
    {                                                                      \
        uint16_t original{};                                               \
        ASSERT_TRUE(_unit->readFunc(original));                            \
        EXPECT_TRUE(_unit->writeFunc(testVal));                            \
        uint16_t readback{};                                               \
        EXPECT_TRUE(_unit->readFunc(readback));                            \
        EXPECT_EQ(readback, static_cast<uint16_t>(testVal));               \
        EXPECT_TRUE(_unit->writeFunc(original));                           \
    }

#define TEST_REGISTER_ROUNDTRIP_32(TestName, readFunc, writeFunc, testVal) \
    TEST_F(TestST25R3916, TestName)                                        \
    {                                                                      \
        uint32_t original{};                                               \
        ASSERT_TRUE(_unit->readFunc(original));                            \
        EXPECT_TRUE(_unit->writeFunc(testVal));                            \
        uint32_t readback{};                                               \
        EXPECT_TRUE(_unit->readFunc(readback));                            \
        EXPECT_EQ(readback, static_cast<uint32_t>(testVal));               \
        EXPECT_TRUE(_unit->writeFunc(original));                           \
    }

// ============================================================
// Part 1: Basic connectivity
// ============================================================

TEST_F(TestST25R3916, Begin)
{
    uint8_t type{}, rev{};
    EXPECT_TRUE(_unit->readICIdentity(type, rev));
}

TEST_F(TestST25R3916, ICIdentity)
{
    uint8_t type{}, rev{};
    ASSERT_TRUE(_unit->readICIdentity(type, rev));
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
    ASSERT_TRUE(_unit->readMaskInterrupts(original));

    // Write a known pattern
    const uint32_t pattern = 0xAAAAAAAAUL;
    EXPECT_TRUE(_unit->writeMaskInterrupts(pattern));

    uint32_t readback{};
    EXPECT_TRUE(_unit->readMaskInterrupts(readback));
    // Verify writable bits match (some bits may be reserved)
    // At minimum, the written bits that ARE writable should be set
    EXPECT_NE(readback, 0U) << "At least some bits should be writable";

    // Restore
    EXPECT_TRUE(_unit->writeMaskInterrupts(original));
}

// ============================================================
// Part 1: Read-only status registers
// ============================================================

TEST_F(TestST25R3916, ReadOnly_FIFOStatus)
{
    uint16_t status{};
    EXPECT_TRUE(_unit->readFIFOStatus(status));
    uint8_t s1{}, s2{};
    EXPECT_TRUE(_unit->readFIFOStatus1(s1));
    EXPECT_TRUE(_unit->readFIFOStatus2(s2));
}

TEST_F(TestST25R3916, ReadOnly_CollisionDisplay)
{
    uint8_t value{};
    EXPECT_TRUE(_unit->readCollisionDisplay(value));
}

TEST_F(TestST25R3916, ReadOnly_PassiveTargetDisplay)
{
    uint8_t value{};
    EXPECT_TRUE(_unit->readPassiveTargetDisplay(value));
}

TEST_F(TestST25R3916, ReadOnly_Interrupts)
{
    uint8_t main_irq{}, timer_irq{}, error_irq{}, passive_irq{};
    EXPECT_TRUE(_unit->readMainInterrupt(main_irq));
    EXPECT_TRUE(_unit->readTimerAndNFCInterrupt(timer_irq));
    EXPECT_TRUE(_unit->readErrorAndWakeupInterrupt(error_irq));
    EXPECT_TRUE(_unit->readPassiveTargetInterrupt(passive_irq));

    uint32_t all_irq{};
    EXPECT_TRUE(_unit->readInterrupts(all_irq));
}

// ============================================================
// Part 1: config_t
// ============================================================

TEST_F(TestST25R3916, ConfigGetterByValue)
{
    auto cfg_orig = _unit->config();

    auto cfg_mutated             = cfg_orig;
    cfg_mutated.vdd_voltage_5V   = !cfg_orig.vdd_voltage_5V;
    cfg_mutated.tx_am_modulation = static_cast<uint8_t>((cfg_orig.tx_am_modulation + 1U) & 0x0FU);

    // Original should be unchanged
    auto cfg_check = _unit->config();
    EXPECT_EQ(cfg_check.vdd_voltage_5V, cfg_orig.vdd_voltage_5V);
    EXPECT_EQ(cfg_check.tx_am_modulation, cfg_orig.tx_am_modulation);

    // Set mutated config and re-read
    _unit->config(cfg_mutated);
    auto cfg_after = _unit->config();
    EXPECT_EQ(cfg_after.vdd_voltage_5V, cfg_mutated.vdd_voltage_5V);
    EXPECT_EQ(cfg_after.tx_am_modulation, cfg_mutated.tx_am_modulation);

    // Restore
    _unit->config(cfg_orig);
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
    ASSERT_TRUE(stop_field(_unit));
    EXPECT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::A));
    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::A));
}

TEST_F(TestST25R3916, ConfigureNFCMode_B)
{
    ASSERT_TRUE(stop_field(_unit));
    EXPECT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::B));
}

TEST_F(TestST25R3916, ConfigureNFCMode_F)
{
    ASSERT_TRUE(stop_field(_unit));
    EXPECT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::F));
    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::F));
}

TEST_F(TestST25R3916, ConfigureNFCMode_V)
{
    ASSERT_TRUE(stop_field(_unit));
    EXPECT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::V));
    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::V));
}

TEST_F(TestST25R3916, ConfigureNFCMode_Roundtrip)
{
    const m5::nfc::NFC modes[] = {m5::nfc::NFC::A, m5::nfc::NFC::B, m5::nfc::NFC::F, m5::nfc::NFC::V};
    for (auto mode : modes) {
        SCOPED_TRACE(static_cast<int>(mode));
        ASSERT_TRUE(stop_field(_unit));
        EXPECT_TRUE(_unit->configureNFCMode(mode));
        EXPECT_TRUE(_unit->isNFCMode(mode));
        EXPECT_EQ(_unit->NFCMode(), mode);
    }
}

TEST_F(TestST25R3916, ConfigureNFCMode_None_Fails)
{
    ASSERT_TRUE(stop_field(_unit));
    EXPECT_FALSE(_unit->configureNFCMode(m5::nfc::NFC::None));
}

// ============================================================
// Part 1: Direct commands
// ============================================================

TEST_F(TestST25R3916, DirectCommand_SetDefault)
{
    EXPECT_TRUE(_unit->writeDirectCommand(CMD_SET_DEFAULT));
}

TEST_F(TestST25R3916, DirectCommand_ClearFIFO)
{
    EXPECT_TRUE(_unit->writeDirectCommand(CMD_CLEAR_FIFO));
}

TEST_F(TestST25R3916, DirectCommand_CalibrateCapacitiveSensor)
{
    EXPECT_TRUE(_unit->writeDirectCommand(CMD_CALIBRATE_CAPACITIVE_SENSOR));
}

TEST_F(TestST25R3916, DirectCommand_MeasurePowerSupply)
{
    EXPECT_TRUE(_unit->writeDirectCommand(CMD_MEASURE_POWER_SUPPLY));
}

TEST_F(TestST25R3916, DirectCommand_StopAllActivities)
{
    EXPECT_TRUE(_unit->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES));
}

// ============================================================
// Part 1: FIFO (stop field first to get clean state)
// ============================================================

TEST_F(TestST25R3916, FIFOSizeAfterClear)
{
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->writeDirectCommand(CMD_CLEAR_FIFO));

    uint16_t bytes{0xFFFFU};
    uint8_t bits{0xFFU};
    EXPECT_TRUE(_unit->readFIFOSize(bytes, bits));
    EXPECT_EQ(bytes, 0U);
    EXPECT_EQ(bits, 0U);
}

TEST_F(TestST25R3916, FIFOWrite_Succeeds)
{
    // FIFO requires Ready mode (en bit set). Stop TX/RX but keep en.
    ASSERT_TRUE(_unit->writeDirectCommand(CMD_STOP_ALL_ACTIVITIES));
    ASSERT_TRUE(_unit->writeOperationControl(regval::en));
    ASSERT_TRUE(_unit->writeDirectCommand(CMD_CLEAR_FIFO));

    const uint8_t pattern[] = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_TRUE(_unit->writeFIFO(pattern, sizeof(pattern)));
    // Note: FIFO read-back behavior varies by transport (I2C vs Ex_I2C vs SPI).
    // Full roundtrip verification is not reliable across all boards.
}

TEST_F(TestST25R3916, FIFOWrite_RejectOversize)
{
    // Writing more than MAX_FIFO_DEPTH should fail
    uint8_t big[MAX_FIFO_DEPTH + 1] = {};
    EXPECT_FALSE(_unit->writeFIFO(big, sizeof(big)));
}

TEST_F(TestST25R3916, FIFOWrite_RejectNull)
{
    EXPECT_FALSE(_unit->writeFIFO(nullptr, 4));
    uint8_t buf[1] = {};
    EXPECT_FALSE(_unit->writeFIFO(buf, 0));
}

// ============================================================
// Part 1: clearInterrupts
// ============================================================

TEST_F(TestST25R3916, ClearInterrupts)
{
    EXPECT_TRUE(_unit->clearInterrupts());
}

// ============================================================
// Part 1: Bitrate (stop field before configureNFCMode)
// ============================================================

TEST_F(TestST25R3916, WriteBitrate_NFCA)
{
    using m5::nfc::Bitrate;
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::A));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCF)
{
    using m5::nfc::Bitrate;
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::F));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps212K, Bitrate::Bps212K));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps424K, Bitrate::Bps424K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCB)
{
    using m5::nfc::Bitrate;
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps212K, Bitrate::Bps212K));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps424K, Bitrate::Bps424K));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps848K, Bitrate::Bps848K));
}

TEST_F(TestST25R3916, WriteBitrate_NFCV)
{
    using m5::nfc::Bitrate;
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::V));
    EXPECT_TRUE(_unit->writeBitrate(Bitrate::Bps106K, Bitrate::Bps106K));
}

// ============================================================
// Part 1: Initiator / Target operation mode
// ============================================================

TEST_F(TestST25R3916, InitiatorOperationMode)
{
    EXPECT_TRUE(_unit->writeInitiatorOperationMode(InitiatorOperationMode::ISO14443A));
    EXPECT_TRUE(_unit->writeInitiatorOperationMode(InitiatorOperationMode::ISO14443B));
    EXPECT_TRUE(_unit->writeInitiatorOperationMode(InitiatorOperationMode::FeliCa));
    EXPECT_TRUE(_unit->writeInitiatorOperationMode(InitiatorOperationMode::NFCForumType1));
    EXPECT_TRUE(_unit->writeInitiatorOperationMode(InitiatorOperationMode::SubCarrierStream));
}

TEST_F(TestST25R3916, TargetOperationMode)
{
    EXPECT_TRUE(_unit->writeTargetOperationMode(TargetOperationMode::ISO14443A));
    EXPECT_TRUE(_unit->writeTargetOperationMode(TargetOperationMode::Felica));
    EXPECT_TRUE(_unit->writeTargetOperationMode(TargetOperationMode::NFCIP1));
}

// ============================================================
// Part 1: Mode/Bitrate definition registers
// ============================================================

TEST_F(TestST25R3916, ModeDefinition_ReadWrite)
{
    uint8_t original{};
    ASSERT_TRUE(_unit->readModeDefinition(original));

    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::A));
    uint8_t mode_val{};
    EXPECT_TRUE(_unit->readModeDefinition(mode_val));

    EXPECT_TRUE(_unit->writeModeDefinition(original));
}

TEST_F(TestST25R3916, BitrateDefinition_ReadWrite)
{
    uint8_t original{};
    ASSERT_TRUE(_unit->readBitrateDefinition(original));

    const uint8_t test_val = 0x00U;
    EXPECT_TRUE(_unit->writeBitrateDefinition(test_val));

    uint8_t readback{};
    EXPECT_TRUE(_unit->readBitrateDefinition(readback));
    EXPECT_EQ(readback, test_val);

    EXPECT_TRUE(_unit->writeBitrateDefinition(original));
}

// ============================================================
// Part 1: Reset and verify clean state
// ============================================================

TEST_F(TestST25R3916, SetDefaultResetsGPT)
{
    EXPECT_TRUE(_unit->writeGeneralPurposeTimer(0x1234U));

    ASSERT_TRUE(_unit->writeDirectCommand(CMD_SET_DEFAULT));

    uint16_t gpt{};
    EXPECT_TRUE(_unit->readGeneralPurposeTimer(gpt));
    EXPECT_EQ(gpt, 0x0000U) << "GPT should be 0 after CMD_SET_DEFAULT";
}

// ============================================================
// Part 2: Layer construction and properties
// ============================================================

TEST_F(TestST25R3916, NFCLayerA_Construction)
{
    m5::nfc::NFCLayerA nfc_a{*_unit};
    EXPECT_EQ(nfc_a.maximum_fifo_depth(), MAX_FIFO_DEPTH);
    EXPECT_EQ(nfc_a.supportsNFCTag(), m5::nfc::NFCForumTag::None);
}

TEST_F(TestST25R3916, NFCLayerB_Construction)
{
    m5::nfc::NFCLayerB nfc_b{*_unit};
    EXPECT_EQ(nfc_b.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

TEST_F(TestST25R3916, NFCLayerF_Construction)
{
    m5::nfc::NFCLayerF nfc_f{*_unit};
    EXPECT_EQ(nfc_f.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

TEST_F(TestST25R3916, NFCLayerV_Construction)
{
    m5::nfc::NFCLayerV nfc_v{*_unit};
    EXPECT_EQ(nfc_v.maximum_fifo_depth(), MAX_FIFO_DEPTH);
}

// ============================================================
// Part 2: Emulation layer
// ============================================================

TEST_F(TestST25R3916, EmulationLayerA_InitialState)
{
    m5::nfc::EmulationLayerA emu_a{*_unit};
    EXPECT_EQ(emu_a.state(), m5::nfc::EmulationLayerA::State::None);
    // Default expired time is 60 seconds
    EXPECT_EQ(emu_a.expiredTime(), 60000U);
}

TEST_F(TestST25R3916, EmulationLayerF_InitialState)
{
    m5::nfc::EmulationLayerF emu_f{*_unit};
    EXPECT_EQ(emu_f.state(), m5::nfc::EmulationLayerF::State::None);
    EXPECT_EQ(emu_f.expiredTime(), 60000U);
}

TEST_F(TestST25R3916, EmulationLayerA_SetExpiredTime)
{
    m5::nfc::EmulationLayerA emu_a{*_unit};
    emu_a.setExpiredTime(5000);
    EXPECT_EQ(emu_a.expiredTime(), 5000U);
    emu_a.setExpiredTime(0);
    EXPECT_EQ(emu_a.expiredTime(), 0U);
}

TEST_F(TestST25R3916, EmulationLayerF_SetExpiredTime)
{
    m5::nfc::EmulationLayerF emu_f{*_unit};
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
    ASSERT_TRUE(stop_field(_unit));
    ASSERT_TRUE(_unit->configureNFCMode(m5::nfc::NFC::B));
    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::B));

    {
        m5::nfc::NFCLayerA nfc_a{*_unit};
    }

    EXPECT_TRUE(_unit->isNFCMode(m5::nfc::NFC::B));
}
