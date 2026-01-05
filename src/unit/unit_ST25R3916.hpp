/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916.hpp
  @brief ST25R3916 Unit for M5UnitUnified
*/
#ifndef M5_UNIT_NFC_UNIT_ST25R3916_HPP
#define M5_UNIT_NFC_UNIT_ST25R3916_HPP

#include <M5UnitComponent.hpp>
#include "ST25R3916_definition.hpp"
#include "nfc/nfc.hpp"
#include "nfc/a/nfca.hpp"
#include "nfc/a/mifare.hpp"
#include "nfc/a/mifare_classic_crypto1.hpp"
#include "nfc/b/nfcb.hpp"
#include "nfc/f/nfcf.hpp"
#include "nfc/v/nfcv.hpp"

namespace m5 {
namespace nfc {
struct ListenerST25R3916ForA;
struct ListenerST25R3916ForF;
}  // namespace nfc
namespace unit {

namespace nfc {
struct AdapterST25R3916;
}  // namespace nfc

/*!
  @class UnitST25R3916
  @brief ST25R3916 Unit
 */
class UnitST25R3916 : public Component {
    M5_UNIT_COMPONENT_HPP_BUILDER(UnitST25R3916, 0x50 /* I2C address */);

public:
    explicit UnitST25R3916(const uint8_t arg = DEFAULT_ADDRESS) : Component(arg)
    {
        auto ccfg  = component_config();
        ccfg.clock = 400 * 1000U;
        component_config(ccfg);
    }
    virtual ~UnitST25R3916() = default;

    virtual bool begin() override;
    virtual void update(const bool force = false) override;

    /*!
      @struct config_t
      @brief Settings for begin
     */
    struct config_t {
        m5::nfc::NFC mode{m5::nfc::NFC::A};  //!< Initial target for Poll/Listen
        bool vdd_voltage_5V{false};          //!< VDD voltage true:5V false:3.3V
        uint8_t tx_am_modulation{13};        //!< 0-15 See also 4.5.48 TX driver register
        bool using_irq{};                    //!< Exists IRQ PIN?
        uint8_t irq{};                       //!< IRQ PIN
        bool emulation{};                    //!< Emulation mode?
    };

    ///@name Settings for begin
    ///@{
    /*! @brief Gets the configration */
    inline config_t config()
    {
        return _cfg;
    }
    //! @brief Set the configration
    inline void config(const config_t& cfg)
    {
        _cfg = cfg;
    }
    ///@}

    //! @brief Gets the current operating mode
    inline m5::nfc::NFC NFCMode() const
    {
        return _nfcMode;
    }
    /*!
      @brief Configure NFC mode
      @param mode NFC mode
      @return True if successful
     */
    bool configureNFCMode(const m5::nfc::NFC mode);
    /*!
      @brief Configure NFC mode for emulation
      @param mode NFC mode
      @return True if successful
     */
    bool configureEmulationMode(const m5::nfc::NFC mode);

    /*!
      @brief Is the current operating mode the one specified?
      @param mode Mode
      @return True if the current operation is in the specified mode
     */
    inline bool isNFCMode(const m5::nfc::NFC mode)
    {
        return NFCMode() == mode;
    }

    /*!
      @brief Write the direct command with data
      @param cmd Direct command
      @param data The data pointer if additional data is available
      @param dlen length of th e additional data
      @return True if successful
     */
    bool writeDirectCommand(const uint8_t cmd, const uint8_t* data = nullptr, const uint32_t dlen = 0u);

    ///@name Interrupt
    ///@{
    /*!
      @brief Clear interrupts flag
      @return True if successful
     */
    bool clearInterrupts();
    ///@}

    ///@name Settings
    ///@{
    /*!
      @brief Write the initiator operation mode and transition to initiator mode
      @details writeModeDefinition
      @param mode InitiatorOperationMode
      @param optional Other setting bits
      @return True if successful
     */
    bool writeInitiatorOperationMode(const st25r3916::InitiatorOperationMode mode, const uint8_t optional = 0);
    /*!
      @brief Write the initiator operation mode and transition to target mode
      @details writeModeDefinition
      @param mode TargetOperationMode
      @param optional Other setting bits
      @return True if successful
     */
    bool writeTargetOperationMode(const st25r3916::TargetOperationMode mode, const uint8_t optional = 0);

    bool writeBitrate(const m5::nfc::Bitrate tx, const m5::nfc::Bitrate rx);
    ///@}

    ///@name FIFO
    ///@{
    /*!
      @brief Read the FIFO size
      @param[out] bytes Number of bytes in the FIFO
      @param[out] bits Number of bits in the last FIFO byte if it was not complete
      The received bits are stored in the LSB part of the last byte in the FIFO.
      @return True if successful
     */
    bool readFIFOSize(uint16_t& bytes, uint8_t& bits);
    /*!
      @brief Read from FIFO
      @param[out] actual Actual read size
      @param[out] buf Buffer
      @param buf_size Buffer size
      @retval == 0 Failed
      @retval != 0 Upper 16 bits: Number of bits read Lower 16 bits: Number of bytes read
     */
    uint32_t readFIFO(uint16_t& actual, uint8_t* buf, const uint16_t buf_size);
    /*!
      @brief Write to FIFO
      @param buf Buffer
      @param buf_size Buffer size
      @return True if successful
     */
    bool writeFIFO(const uint8_t* buf, const uint16_t buf_size);
    ///@}

    ///@name I/O configuration
    ///@{
    /*!
      @brief Read the I/O configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readIOConfiguration1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_IO_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the I/O configuration 1
      @param value Value
      @return True if successful
     */
    inline bool writeIOConfiguration1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_IO_CONFIGURATION_1, value);
    }
    /*!
      @brief Read the I/O configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readIOConfiguration2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_IO_CONFIGURATION_2, value);
    }
    /*!
      Write the I/O configuration 1
      @param value Value
      @return True if successful
     */
    inline bool writeIOConfiguration2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_IO_CONFIGURATION_2, value);
    }
    /*!
      @brief Read the I/O configuration 1-2
      @param[out] value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool readIOConfiguration(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_IO_CONFIGURATION_1, value);
    }
    /*!
      Write the I/O configuration 1-2
      @param value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool writeIOConfiguration(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_IO_CONFIGURATION_1, value);
    }
    ///@}

    ///@name Operation control and mode definition
    ///@{
    /*!
      @brief Read the operation control
      @param[out] value Value
      @return True if successful
     */
    inline bool readOperationControl(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_OPERATION_CONTROL, value);
    }
    /*!
      @brief Write the operation control
      @param value Value
      @return True if successful
     */
    inline bool writeOperationControl(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_OPERATION_CONTROL, value);
    }
    /*!
      @brief Read the mode definition
      @param[out] value Value
      @return True if successful
     */
    inline bool readModeDefinition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MODE_DEFINITION, value);
    }
    /*!
      @brief Write the mode definition
      @param value Value
      @return True if successful
     */
    inline bool writeModeDefinition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_MODE_DEFINITION, value);
    }
    /*!
      @brief Read the bitrate definition
      @param[out] value Value
      @return True if successful
     */
    inline bool readBitrateDefinition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_BITRATE_DEFINITION, value);
    }
    /*!
      @brief Write the bitrate definition
      @param value Value
      @return True if successful
     */
    inline bool writeBitrateDefinition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_BITRATE_DEFINITION, value);
    }
    ///@}

    ///@name Protocol configuration
    ///@{
    /*!
      @brief Read the settings for ISO14443A and NFC 106kb/s
      @param[out] value Value
      @return True if successful
     */
    inline bool readSettingsISO14443A(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_ISO14443A_SETTINGS, value);
    }
    /*!
      @brief Write the settings for ISO14443A and NFC 106kb/s
      @param value Value
      @return True if successful
     */
    inline bool writeSettingsISO14443A(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_ISO14443A_SETTINGS, value);
    }
    /*!
      @brief Read the settings for ISO14443B
      @param[out] value Value
      @return True if successful
     */
    inline bool readSettingsISO14443B(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_ISO14443B_SETTINGS, value);
    }
    /*!
      @brief Write the settings for ISO14443B
      @param value Value
      @return True if successful
     */
    inline bool writeSettingsISO14443B(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_ISO14443B_SETTINGS, value);
    }
    /*!
      @brief Read the settings for ISO14443B and FeliCa
      @param[out] value Value
      @return True if successful
     */
    inline bool readSettingsFelica(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_FELICA_SETTINGS, value);
    }
    /*!
      @brief Write the settings for ISO14443B and FeliCa
      @param value Value
      @return True if successful
     */
    inline bool writeSettingsFelica(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_FELICA_SETTINGS, value);
    }
    /*!
      @brief Read the NFCIP-1 passive target definition
      @param[out] value Value
      @return True if successful
     */
    inline bool readNFCIP1PassiveTargetDefinition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, value);
    }
    /*!
      Write the NFCIP-1 passive target definition
      @param[out] value Value
      @return True if successful
     */
    inline bool writeNFCIP1PassiveTargetDefinition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, value);
    }
    /*!
      @brief Read the stream mode definition
      @param[out] value Value
      @return True if successful
     */
    inline bool readStreamModeDefinition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_STREAM_MODE_DEFINITION, value);
    }
    /*!
      @brief Write the stream mode definition
      @param value Value
      @return True if successful
     */
    inline bool writeStreamModeDefinition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_STREAM_MODE_DEFINITION, value);
    }
    /*!
      @brief Read the Auxiliary definition
      @param[out] value Value
      @return True if successful
     */
    inline bool readAuxiliaryDefinition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AUXILIARY_DEFINITION, value);
    }
    /*!
      @brief Write the Auxiliary definition
      @param value Value
      @return True if successful
     */
    inline bool writeAuxiliaryDefinition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_AUXILIARY_DEFINITION, value);
    }

    /*!
      @brief Read the EMD suppression configuration
      @param[out] value Value
      @return True if successful
     */
    inline bool readEMDSuppressionConfiguration(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_EMD_SUPPRESSION_CONFIGURATION, value);
    }
    /*!
      @brief Write the EMD suppression configuration
      @param value Value
      @return True if successful
     */
    inline bool writeEMDSuppressionConfiguration(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_EMD_SUPPRESSION_CONFIGURATION, value);
    }
    /*!
      @brief Read the subcarrier start timer
      @param[out] value Value
      @return True if successful
     */
    inline bool readSubcarrierStartTimer(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_SUBCARRIER_START_TIMER, value);
    }
    /*!
      @brief Write the subcarrier start timer
      @param value Value
      @return True if successful
     */
    inline bool writeSubcarrierStartTimer(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_SUBCARRIER_START_TIMER, value);
    }
    ///@}

    ///@name Receiver configuration
    ///@{
    /*!
      @brief Read the receiver configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readReceiverConfiguration1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the receiver configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool writeReceiverConfiguration1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_1, value);
    }
    /*!
      @brief Read the receiver configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readReceiverConfiguration2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_2, value);
    }
    /*!
      @brief Write the receiver configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool writeReceiverConfiguration2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_2, value);
    }
    /*!
      @brief Read the receiver configuration 3
      @param[out] value Value
      @return True if successful
     */
    inline bool readReceiverConfiguration3(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_3, value);
    }
    /*!
      @brief Write the receiver configuration 3
      @param[out] value Value
      @return True if successful
     */
    inline bool writeReceiverConfiguration3(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_3, value);
    }
    /*!
      Read the receiver configuration 4
      @param[out] value Value
      @return True if successful
     */
    inline bool readReceiverConfiguration4(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_4, value);
    }
    /*!
      @brief Write the receiver configuration 4
      @param[out] value Value
      @return True if successful
     */
    inline bool writeReceiverConfiguration4(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_RECEIVER_CONFIGURATION_4, value);
    }
    /*!
      @brief Read the receiver configuration 1-4
      @param[out] value Value (MSB cfg1,cfg2,cfg3,cfg4 LSB)
      @return True if successful
     */
    inline bool readReceiverConfiguration(uint32_t& value)
    {
        return read_register32(st25r3916::command::REG_RECEIVER_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the receiver configuration 1-4
      @param value Value (MSB cfg1,cfg2,cfg3,cfg4 LSB)
      @return True if successful
     */
    inline bool writeReceiverConfiguration(const uint32_t value)
    {
        return write_register32(st25r3916::command::REG_RECEIVER_CONFIGURATION_1, value);
    }

    /*!
      @brief Read the P2P receiver configuration
      @param[out] value Value
      @return True if successful
     */
    inline bool readP2PReceiverConfiguration(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_P2P_RECEIVER_CONFIGURATION, value);
    }
    /*!
      @brief Write the P2P receiver configuration
      @param value Value
      @return True if successful
     */
    inline bool writeP2PReceiverConfiguration(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_P2P_RECEIVER_CONFIGURATION, value);
    }
    /*!
      @brief Read the correlator configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readCorrelatorConfiguration1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CORRELATOR_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the correlator configuration 1
      @param value Value
      @return True if successful
     */
    inline bool writeCorrelatorConfiguration1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_CORRELATOR_CONFIGURATION_1, value);
    }
    /*!
      @brief Read the correlator configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readCorrelatorConfiguration2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CORRELATOR_CONFIGURATION_2, value);
    }
    /*!
      @brief Write the correlator configuration 2
      @param value Value
      @return True if successful
     */
    inline bool writeCorrelatorConfiguration2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_CORRELATOR_CONFIGURATION_2, value);
    }
    /*!
      @brief Read the correlator configuration 1-2
      @param[out] value Value (MSB cfg1,cfg2 LSB)
      @return True if successful
     */
    inline bool readCorrelatorConfiguration(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_CORRELATOR_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the correlator configuration 1-2
      @param value Value (MSB cfg1,cfg2 LSB)
      @return True if successful
     */
    inline bool writeCorrelatorConfiguration(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_CORRELATOR_CONFIGURATION_1, value);
    }
    ///@}

    ///@name Timer definition
    ///@{
    /*!
      @brief Read the mask receive timer
      @param[out] value Value
      @return True if successful
     */
    inline bool readMaskReceiveTimer(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MASK_RECEIVER_TIMER, value);
    }
    /*!
      @brief Write the mask receive timer
      @param value Value
      @return True if successful
     */
    inline bool writeMaskReceiveTimer(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_MASK_RECEIVER_TIMER, value);
    }
    /*!
      @brief Read the no-response timer 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readNoResponseTimer1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NO_RESPONSE_TIMER_1, value);
    }
    /*!
      @brief Write the no-response timer 1
      @param value Value
      @return True if successful
     */
    inline bool writeNoResponseTimer1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NO_RESPONSE_TIMER_1, value);
    }
    /*!
      @brief Read the no-response timer 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readNoResponseTimer2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NO_RESPONSE_TIMER_2, value);
    }
    /*!
      @brief Write the no-response timer 2
      @param value Value
      @return True if successful
     */
    inline bool writeNoResponseTimer2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NO_RESPONSE_TIMER_2, value);
    }
    /*!
      @brief Read the no-response timer 1-2
      @param[out] value Value (MSB timer1, timer2 LSB)
      @return True if successful
     */
    inline bool readNoResponseTimer(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_NO_RESPONSE_TIMER_1, value);
    }
    /*!
      @brief Write the no-response timer 1-2
      @param value Value (MSB timer1, timer2 LSB)
      @return True if successful
     */
    inline bool writeNoResponseTimer(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_NO_RESPONSE_TIMER_1, value);
    }
    /*!
      @brief Read the timer and EMV control
      @param[out] value Value
      @return True if successful
     */
    inline bool readTimerAndEMVControl(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_TIMER_AND_EMV_CONTROL, value);
    }
    /*!
      @brief Write the timer and EMV control
      @param value Value
      @return True if successful
     */
    inline bool writeTimerAndEMVControl(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_TIMER_AND_EMV_CONTROL, value);
    }
    /*!
      @brief Read the general purpose timer 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readGeneralPurposeTimer1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_1, value);
    }
    /*!
      @brief Write the general purpose timer 1
      @param value Value
      @return True if successful
     */
    inline bool writeGeneralPurposeTimer1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_1, value);
    }
    /*!
      @brief Read the general purpose timer 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readGeneralPurposeTimer2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_2, value);
    }
    /*!
      @brief Write the general purpose timer 2
      @param value Value
      @return True if successful
     */
    inline bool writeGeneralPurposeTimer2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_2, value);
    }
    /*!
      @brief Read the general purpose timer 1-2
      @param[out] value Value (MSB timer1,timer2 LSB)
      @return True if successful
     */
    inline bool readGeneralPurposeTimer(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_1, value);
    }
    /*!
      @brief Write the general purpose timer 1-2
      @param value Value (MSB timer1,timer2 LSB)
      @return True if successful
     */
    inline bool writeGeneralPurposeTimer(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_GENERAL_PURPOSE_TIMER_1, value);
    }
    /*!
      @brief Read the PPON2 field waiting
      @param[out] value Value
      @return True if successful
     */
    inline bool readPPON2FieldWaiting(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PPON2_FIELD_WAITING, value);
    }
    /*!
      @brief Write the PPON2 field waiting
      @param value Value
      @return True if successful
     */
    inline bool writePPON2FieldWaiting(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_PPON2_FIELD_WAITING, value);
    }

    /*!
      @brief Read the squelch timer
      @param[out] value Value
      @return True if successful
     */
    inline bool readSquelchTimer(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_SQUELCH_TIMER, value);
    }
    /*!
      @brief Write the squelch timer
      @param value Value
      @return True if successful
     */
    inline bool writeSquelchTimer(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_SQUELCH_TIMER, value);
    }
    /*!
      @brief Read the NFC field on guard timer
      @param[out] value Value
      @return True if successful
     */
    inline bool readNFCFieldOnGuardTimer(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NFC_FIELD_ON_GUARD_TIMER, value);
    }
    /*!
      @brief Write the NFC field on guard timer
      @param value Value
      @return True if successful
     */
    inline bool writeNFCFieldOnGuardTimer(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NFC_FIELD_ON_GUARD_TIMER, value);
    }
    ///@}

    ///@name Interrupt and associated reporting
    ///@{
    /*!
      @brief Read the mask main interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readMaskMainInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value);
    }
    /*!
      @brief Write the mask main interrupt
      @param value Value
      @return True if successful
     */
    inline bool writeMaskMainInterrupt(const uint8_t value)
    {
        if (write_register8(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value)) {
            _enabled_irq = (_enabled_irq & 0x00FFFFFF) | ((uint32_t)~value << 24);
            return true;
        }
        return false;
    }
    /*!
      @brief Read the mask timer and NFC interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readMaskTimerAndNFCInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MASK_TIMER_AND_NFC_INTERRUPT, value);
    }
    /*!
      @brief Write the mask timer and NFC interrupt
      @param value Value
      @return True if successful
     */
    inline bool writeMaskTimerAndNFCInterrupt(const uint8_t value)
    {
        if (write_register8(st25r3916::command::REG_MASK_TIMER_AND_NFC_INTERRUPT, value)) {
            _enabled_irq = (_enabled_irq & 0xFF00FFFF) | ((uint32_t)~value << 16);
            return true;
        }
        return false;
    }
    /*!
      @brief Read the mask error and wake-up interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readMaskErrorAndWakeupInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MASK_ERROR_AND_WAKEUP_INTERRUPT, value);
    }
    /*!
      @brief Write the mask error and wake-up interrupt
      @param value Value
      @return True if successful
     */
    inline bool writeMaskErrorAndWakeupInterrupt(const uint8_t value)
    {
        if (write_register8(st25r3916::command::REG_MASK_ERROR_AND_WAKEUP_INTERRUPT, value)) {
            _enabled_irq = (_enabled_irq & 0xFFFF00FF) | ((uint32_t)~value << 8);
            return true;
        }
        return false;
    }
    /*!
      @brief Read the mask passive target interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readMaskPassiveTargetInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MASK_PASSIVE_TARGET_INTERRUPT, value);
    }
    /*!
      @brief Write the mask passive target interrupt
      @param value Value
      @return True if successful
     */
    inline bool writeMaskPassiveTargetInterrupt(const uint8_t value)
    {
        if (write_register8(st25r3916::command::REG_MASK_PASSIVE_TARGET_INTERRUPT, value)) {
            _enabled_irq = (_enabled_irq & 0xFFFFFF00) | (uint32_t)~value;
            return true;
        }
        return false;
    }
    /*!
      @brief Read the all mask
      @param[out] value Value (MSB main, NFC, error, passive LSB)
      @return True if successful
     */
    inline bool readMaskInterrupts(uint32_t& value)
    {
        return read_register32(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value);
    }
    /*!
      @brief Write the all mask
      @param value Value (MSB main, NFC, error, passive LSB)
      @return True if successful
     */
    inline bool writeMaskInterrupts(const uint32_t value)
    {
        if (write_register32(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value)) {
            _enabled_irq = ~value;
            return true;
        }
        return false;
    }

    /*!
      @brief Read the main interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readMainInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_MAIN_INTERRUPT, value);
    }
    /*!
      @brief Read the timer and NFC interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readTimerAndNFCInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_TIMER_AND_NFC_INTERRUPT, value);
    }
    /*!
      @brief Read the error and wake-up interrupt
      @param[out] value Value
      @return True if successful
      @warning After Main interrupt register has been read, its content is set to 0
     */
    inline bool readErrorAndWakeupInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_ERROR_AND_WAKEUP_INTERRUPT, value);
    }
    /*!
      @brief Read the passive target interrupt
      @param[out] value Value
      @return True if successful
     */
    inline bool readPassiveTargetInterrupt(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PASSIVE_TARGET_INTERRUPT, value);
    }
    /*!
      @brief Read the all interrupt
      @param[out] value Value (MSB main, NFC, error, passive LSB)
      @return True if successful
     */
    bool readInterrupts(uint32_t& value);

    /*!
      @brief Read the FIFO status 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readFIFOStatus1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_FIFO_STATUS_1, value);
    }
    /*!
      @brief Read the FIFO status 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readFIFOStatus2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_FIFO_STATUS_2, value);
    }
    /*!
      @brief Read the FIFO status 1-2
      @param[out] value Value (MSB fifo1, fifo2 LSB)
      @return True if successful
     */
    inline bool readFIFOStatus(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_FIFO_STATUS_1, value);
    }

    /*!
      @brief Read the collision display
      @param[out] value Value
      @return True if successful
     */
    inline bool readCollisionDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_COLLISION_DISPLAY, value);
    }
    /*!
      @brief Read the passive target
      @param[out] value Value
      @return True if successful
     */
    inline bool readPassiveTargetDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PASSIVE_TARGET_DISPLAY, value);
    }
    ///@}

    ///@name Definition of number of transmitted bytes
    ///@{
    /*!
      @brief Read the number of transmitted bytes 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readNumberOfTransmittedBytes1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_1, value);
    }
    /*!
      @brief Write the number of transmitted bytes 1
      @param value Value
      @return True if successful
     */
    inline bool writeNumberOfTransmittedBytes1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_1, value);
    }
    /*!
      @brief Read the number of transmitted bytes 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readNumberOfTransmittedBytes2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_2, value);
    }
    /*!
      @brief Write the number of transmitted bytes 2
      @param value Value
      @return True if successful
     */
    inline bool writeNumberOfTransmittedBytes2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_2, value);
    }
    /*!
      @brief Read the number of transmitted bytes 1-2
      @param[out] value Value (MSB bytes1, bytes2 LSB)
      @return True if successful
     */
    inline bool readNumberOfTransmittedBytes(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_1, value);
    }
    /*!
      @brief Write the number of transmitted bytes 1-2
      @param value Value (MSB bytes1, bytes2 LSB)
      @return True if successful
     */
    inline bool writeNumberOfTransmittedBytes(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_NUMBER_OF_TRANSMITTED_BYTES_1, value);
    }

    /*!
      @brief Write the number of transmitted bytes and after bytes
      @param bytes Number of full bytes to be transmitted
      @param afterBytes Number of bits to transmit after the last full byte
      @return True if successful
     */
    inline bool writeNumberOfTransmittedBytes(const uint16_t bytes, const uint8_t bits)
    {
        // M5_LIB_LOGD("TransmitBytes:%u, %u", bytes, bits);
        return writeNumberOfTransmittedBytes(((bytes & 0x01FF) << 3 /* ntx 0-12 */) | (bits & 0x07 /*nbtx 0-2*/));
    }

    /*!
      @brief Read the bit rate detection display
      @param[out] value Value
      @return True if successful
     */
    inline bool readBitrateDetectionDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_BITRATE_DETECTION_DISPLAY, value);
    }
    ///@}

    ///@name A/D converter output
    ///@{
    /*!
      @brief Read the number of transmitted bytes 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readADConverterOutput(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AD_CONVERTER_OUTPUT, value);
    }
    ///@}

    ///@name Antenna calibration
    ///@{
    /*!
      @brief Read the Antenna tuning control 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readAntennaTuningControl1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_1, value);
    }
    /*!
      @brief Write the Antenna tuning control 1
      @param value Value
      @return True if successful
     */
    inline bool writeAntennaTuningControl1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_1, value);
    }
    /*!
      @brief Read the Antenna tuning control 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readAntennaTuningControl2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_2, value);
    }
    /*!
      @brief Write the Antenna tuning control 2
      @param value Value
      @return True if successful
     */
    inline bool writeAntennaTuningControl2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_2, value);
    }
    /*!
      @brief Read the Antenna tuning control 1-2
      @param[out] value Value (MSB tuning1, tuning2 LSB)
      @return True if successful
     */
    inline bool readAntennaTuningControl(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_1, value);
    }
    /*!
      @brief Write the Antenna tuning control 1-2
      @param value Value (MSB tuning1, tuning2 LSB)
      @return True if successful
     */
    inline bool writeAntennaTuningControl(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_ANTENNA_TUNING_CONTROL_1, value);
    }
    ///@}

    ///@name Antenna driver and modulation
    ///@{
    /*!
      @brief Read the TX driver
      @param[out] value Value
      @return True if successful
     */
    inline bool readTXDriver(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_TX_DRIVER, value);
    }
    /*!
      @brief Write the TX driver
      @param value Value
      @return True if successful
     */
    inline bool writeTXDriver(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_TX_DRIVER, value);
    }
    /*!
      @brief Read the passive target modulation
      @param[out] value Value
      @return True if successful
     */
    inline bool readPassiveTargetModulation(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PASSIVE_TARGET_MODULATION, value);
    }
    /*!
      @brief Write the passive target modulation
      @param value Value
      @return True if successful
     */
    inline bool writePassiveTargetModulation(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_PASSIVE_TARGET_MODULATION, value);
    }

    /*!
      @brief Read the auxiliary modulation setting
      @param[out] value Value
      @return True if successful
     */
    inline bool readAuxiliaryModulationSetting(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AUXILIARY_MODULATION_SETTING, value);
    }
    /*!
      @brief Write the auxiliary modulation setting
      @param[out] value Value
      @return True if successful
     */
    inline bool writeAuxiliaryModulationSetting(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_AUXILIARY_MODULATION_SETTING, value);
    }
    /*!
      @brief Read the TX driver timing
      @param[out] value Value
      @return True if successful
     */
    inline bool readTXDriverTiming(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_TX_DRIVER_TIMING, value);
    }
    /*!
      @brief Write the TX driver timing
      @param[out] value Value
      @return True if successful
     */
    inline bool writeTXDriverTiming(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_TX_DRIVER_TIMING, value);
    }
    ///@}

    ///@name External field detector threshold
    ///@{
    /*!
      @brief Read the external field detector activation threshold
      @param[out] value Value
      @return True if successful
     */
    inline bool readExternalFieldDetectorActivationThreshold(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_EXTERNAL_FIELD_DETECTOR_ACTIVATION_THRESHOLD, value);
    }
    /*!
      @brief Write the external field detector activation threshold
      @param value Value
      @return True if successful
     */
    inline bool writeExternalFieldDetectorActivationThreshold(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_EXTERNAL_FIELD_DETECTOR_ACTIVATION_THRESHOLD, value);
    }
    /*!
      @brief Read the external field detector deactivation threshold
      @param[out] value Value
      @return True if successful
     */
    inline bool readExternalFieldDetectorDeactivationThreshold(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_EXTERNAL_FIELD_DETECTOR_DEACTIVATION_THRESHOLD, value);
    }
    /*!
      @brief Write the external field detector deactivation threshold
      @param value Value
      @return True if successful
     */
    inline bool writeExternalFieldDetectorDeactivationThreshold(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_EXTERNAL_FIELD_DETECTOR_DEACTIVATION_THRESHOLD, value);
    }

    /*!
      @brief Read the resistive AM modulation
      @param[out] value Value
      @return True if successful
     */
    inline bool readResistiveAMModulation(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RESISTIVE_AM_MODULATION, value);
    }
    /*!
      @brief Write the resistive AM modulation
      @param value Value
      @return True if successful
     */
    inline bool writeResistiveAMModulation(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_RESISTIVE_AM_MODULATION, value);
    }
    /*!
      @brief Read the TX driver timing display
      @param[out] value Value
      @return True if successful
     */
    inline bool readTXDriverTimingDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_TX_DRIVER_TIMING_DISPLAY, value);
    }
    ///@}

    ///@name Regulator
    ///@{
    /*!
      @brief Read the regulator voltage control
      @param[out] value Value
      @return True if successful
     */
    inline bool readRegulatorVoltageControl(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_REGULATOR_VOLTAGE_CONTROL, value);
    }
    /*!
      @brief Write the regulator voltage control
      @param value Value
      @return True if successful
     */
    inline bool writeRegulatorVoltageControl(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_REGULATOR_VOLTAGE_CONTROL, value);
    }
    /*!
      @brief Read the regulator display
      @param[out] value Value
      @return True if successful
     */
    inline bool readRegulatorDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_REGULATOR_DISPLAY, value);
    }
    ///@}

    ///@name Receiver state display
    ///@{
    /*!
      @brief Read the external field detector deactivation threshold
      @param[out] value Value
      @return True if successful
     */
    inline bool readRSSIDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_RSSI_DISPLAY, value);
    }
    /*!
      @brief Read the gain reduction state
      @param[out] value Value
      @return True if successful
     */
    inline bool readGainReductionState(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_GAIN_REDUCTION_STATE, value);
    }
    ///@}

    ///@name Capacitive sensor
    ///@{
    /*!
      @brief Read the capacitive sensor control
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitiveSensorControl(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITIVE_SENSOR_CONTROL, value);
    }
    /*!
      @brief Write the capacitive sensor control
      @param value Value
      @return True if successful
     */
    inline bool writeCapacitiveSensorControl(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_CAPACITIVE_SENSOR_CONTROL, value);
    }
    /*!
      @brief Read the capacitive sensor display
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitiveSensorDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITIVE_SENSOR_DISPLAY, value);
    }
    ///@}

    ///@name Auxiliary display
    ///@{
    /*!
      @brief Read the auxiliary display
      @param[out] value Value
      @return True if successful
     */
    inline bool readAuxiliaryDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AUXILIARY_DISPLAY, value);
    }
    ///@}

    ///@name Wake-up
    ///@{
    /*!
      @brief Read the Wake-up timer control
      @param[out] value Value
      @return True if successful
     */
    inline bool readWakeupTimerControl(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_WAKEUP_TIMER_CONTROL, value);
    }
    /*!
      @brief Write the Wake-up timer control
      @param value Value
      @return True if successful
     */
    inline bool writeWakeupTimerControl(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_WAKEUP_TIMER_CONTROL, value);
    }

    /*!
      @brief Read the amplitude measurement configuration
      @param[out] value Value
      @return True if successful
     */
    inline bool readAmplitudeMeasurementConfiguration(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Write the amplitude measurement configuration
      @param value Value
      @return True if successful
     */
    inline bool writeAmplitudeMeasurementConfiguration(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Read the amplitude measurement reference
      @param[out] value Value
      @return True if successful
     */
    inline bool readAmplitudeMeasurementReference(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Write the amplitude measurement reference
      @param value Value
      @return True if successful
     */
    inline bool writeAmplitudeMeasurementReference(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Read the amplitude measurement auto-averaging display
      @param[out] value Value
      @return True if successful
     */
    inline bool readAmplitudeMeasurementAutoAveragingDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_AUTO_AVERAGING_DISPLAY, value);
    }
    /*!
      @brief Read the amplitude measurement display
      @param[out] value Value
      @return True if successful
     */
    inline bool readAmplitudeMeasurementDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_AMPLITUDE_MEASUREMENT_DISPLAY, value);
    }

    /*!
      @brief Read the phase measurement configuration
      @param[out] value Value
      @return True if successful
     */
    inline bool readPhaseMeasurementConfiguration(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PHASE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Write the phase measurement configuration
      @param value Value
      @return True if successful
     */
    inline bool writePhaseMeasurementConfiguration(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_PHASE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Read the phase measurement reference
      @param[out] value Value
      @return True if successful
     */
    inline bool readPhaseMeasurementReference(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PHASE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Write the phase measurement reference
      @param value Value
      @return True if successful
     */
    inline bool writePhaseMeasurementReference(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_PHASE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Read the phase measurement auto-averaging display
      @param[out] value Value
      @return True if successful
     */
    inline bool readPhaseMeasurementAutoAveragingDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PHASE_MEASUREMENT_AUTO_AVERAGING_DISPLAY, value);
    }
    /*!
      @brief Read the phase measurement display
      @param[out] value Value
      @return True if successful
     */
    inline bool readPhaseMeasurementDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_PHASE_MEASUREMENT_DISPLAY, value);
    }

    /*!
      @brief Read the capacitance measurement configuration
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitanceMeasurementConfiguration(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Write the capacitance measurement configuration
      @param value Value
      @return True if successful
     */
    inline bool writeCapacitanceMeasurementConfiguration(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_CONFIGURATION, value);
    }
    /*!
      @brief Read the capacitance measurement reference
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitanceMeasurementReference(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Write the capacitance measurement reference
      @param value Value
      @return True if successful
     */
    inline bool writeCapacitanceMeasurementReference(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_REFERENCE, value);
    }
    /*!
      @brief Read the capacitance measurement auto-averaging display
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitanceMeasurementAutoAveragingDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_AUTO_AVERAGING_DISPLAY, value);
    }
    /*!
      @brief Read the capacitance measurement display
      @param[out] value Value
      @return True if successful
     */
    inline bool readCapacitanceMeasurementDisplay(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_CAPACITANCE_MEASUREMENT_DISPLAY, value);
    }
    ///@}

    ///@name Protection
    ///@{
    /*!
      @brief Read the overshoot protection configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readOvershootProtectionConfiguration1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the overshoot protection configuration 1
      @param value Value
      @return True if successful
     */
    inline bool writeOvershootProtectionConfiguration1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Read the overshoot protection configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readOvershootProtectionConfiguration2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_2, value);
    }
    /*!
      @brief Write the overshoot protection configuration 2
      @param value Value
      @return True if successful
     */
    inline bool writeOvershootProtectionConfiguration2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_2, value);
    }
    /*!
      @brief Read the overshoot protection configuration 1-2
      @param[out] value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool readOvershootProtectionConfiguration(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the overshoot protection configuration 1-2
      @param value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool writeOvershootProtectionConfiguration(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_OVERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }

    /*!
      @brief Read the undershoot protection configuration 1
      @param[out] value Value
      @return True if successful
     */
    inline bool readUndershootProtectionConfiguration1(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the undershoot protection configuration 1
      @param value Value
      @return True if successful
     */
    inline bool writeUndershootProtectionConfiguration1(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Read the undershoot protection configuration 2
      @param[out] value Value
      @return True if successful
     */
    inline bool readUndershootProtectionConfiguration2(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_2, value);
    }
    /*!
      @brief Write the undershoot protection configuration 2
      @param value Value
      @return True if successful
     */
    inline bool writeUndershootProtectionConfiguration2(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_2, value);
    }
    /*!
      @brief Read the undershoot protection configuration 1-2
      @param[out] value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool readUndershootProtectionConfiguration(uint16_t& value)
    {
        return read_register16(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    /*!
      @brief Write the undershoot protection configuration 1-2
      @param value Value (MSB cfg1, cfg2 LSB)
      @return True if successful
     */
    inline bool writeUndershootProtectionConfiguration(const uint16_t value)
    {
        return write_register16(st25r3916::command::REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1, value);
    }
    ///@}

    ///@name IC identity
    ///@{
    /*!
      @brief Read th IC identity
      @param[out] type 5-bit IC type code (00101: ST25R3916/7)
      @param[out] rev 3-bit IC revision code (010: rev 3.1)
      @return True if successful
     */
    bool readICIdentity(uint8_t& type, uint8_t& rev);
    ///@}

    ///@name Field
    ///@{
    /*!
      @brief Disable the Field to stop communication with the PICC
      @return True if successful
      @note Disconnect power supply to the PICC
     */
    bool disableField();
    /*!
      @brief Enable the Field to begin communication with the PICC
      @return True if successful
      @brief Begin supplying power to the PICC
     */
    bool enableField();
    ///@}

    // ----------------------------------------------------------------------------------------------
    ///@name NFC-A
    ///@{
    /*!
      @brief Transceive
      @param rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @retval == 0 Failed
      @retval != 0 Upper 16 bits: Number of bits read Lower 16 bits: Number of bytes read
     */
    uint32_t nfcaTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms);
    bool nfcaTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);
    bool nfcaReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms);

    /*!
      @brief Request for idle PICC
      @param[out atqa ATQA
      @return True if successful
     */
    inline bool nfcaRequest(uint16_t& atqa)
    {
        return nfca_request_wakeup(atqa, true);
    }
    /*!
      @brief Wakeup for idle/halt PICC
      @param[out atqa ATQA
      @return True if successful
     */
    inline bool nfcaWakeup(uint16_t& atqa)
    {
        return nfca_request_wakeup(atqa, false);
    }
    /*!
      @brief Select PICC with anti-collision
      @param[out] completed Completed select?
      @param[out]  picc Selected PICC
      @param lv Cascade level (1-3)
      @return True if successful
      @warning The type of activated PICC is determined solely by SAK and is provisional
     */
    bool nfcaSelectWithAnticollision(bool& completed, m5::nfc::a::PICC& picc, const uint8_t lv);
    /*!
      @brief Select specific PICC
      @param  picc  PICC
      @return True if successful
     */
    bool nfcaSelect(const m5::nfc::a::PICC& picc);
    /*!
      @brief Read the 1 block / 4 pages (16 bytes)
      @param rx Receiver buffer (at least 16 bytes)
      @param block Block/Page address
      @return True if successful
      @pre The block must be authenticated if MIFARE classic
     */
    bool nfcaReadBlock(uint8_t rx[16], const uint8_t block);
    /*!
      @brief Write the 1 block / 4 pages (16 bytes)
      @param tx Send buffer (at least 16 bytes)
      @return True if successful
      @pre The block must be authenticated if MIFARE classic
     */
    bool nfcaWriteBlock(const uint8_t block, const uint8_t tx[16]);
    /*!
      @brief Write the 1 page (4 bytes)
      @param tx Send buffer (at least 4 bytes)
      @return True if successful
      @pre The block must be authenticated if MIFARE classic
     */
    bool nfcaWritePage(const uint8_t page, const uint8_t tx[4]);

    /*!
      @brief Hlt for PICC
      @return True if successful
     */
    bool nfcaHlt();

    /*!
      @brief Request for answer to select (RATS)
      @param[out] ats Answer to select (ATS)
      @param fsdi Frame Size for PCD Integer
      @param cid Card Identifier
      @return True if successful
     */
    bool nfcaRequestATS(m5::nfc::a::ATS& ats, const uint8_t fsdi = 5, const uint8_t cid = 0);
    /*!
      @brief Deselect ISO/IEC 14443-4 PICC
      @return True if successful
      @note Call before nfcaHlt if ISO/IEC 14443-4 PICC
     */
    bool nfcaDeselect();
    ///@}

    // ----------------------------------------------------------------------------------------------
    ///@name MIFARE
    ///@{
    /*!
      @brief Authentication using keyA of the specified block
      @param picc PICC
      @param block Block address
      @param key MIFARE classic key
      @return True if successful
     */
    inline bool mifareClassicAuthenticateA(
        const m5::nfc::a::PICC& picc, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY)
    {
        return mifare_classic_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_A, picc, block, key);
    }
    /*!
      @brief Authentication using keyB of the specified block
      @param picc PICC
      @param block Block address
      @param key MIFARE classic key
      @return True if successful
     */
    inline bool mifareClassicAuthenticateB(
        const m5::nfc::a::PICC& picc, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY)
    {
        return mifare_classic_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_B, picc, block, key);
    }
    /*!
      @brief Operation for the value block
      @param cmd Command
      @param block Block address
      @param arg Arrgument for command if needs
      @return True if successful
     */
    bool mifareClassicValueBlock(const m5::nfc::a::Command cmd, const uint8_t block, const uint32_t arg = 0);

    /*!
      @brief Authentication step 1 for UltralightC
      @param[out] ek ek(RndB) 8-byte encrypted PICC random number RndB
      @return True if successful
     */
    bool mifareUltralightCAuthenticate1(uint8_t ek[8]);
    /*!
      @brief Authentication step 1 for UltralightC
      @param[out] rx_ek ek(RndA') 8-byte encrypted, shifted PCD random number RndA'
      @param tx_ek ek(RandA || RndB') 16-byte encrypted random numbers RNDA concatenated by RndB'
      @return True if successful
     */
    bool mifareUltralightCAuthenticate2(uint8_t rx_ek[8], const uint8_t tx_ek[16]);
    /*!
      @brief GetVersion (L3)
      @param[out] ver Version information
      @return True if successful
     */
    bool mifareGetVersion3(uint8_t ver[8]);
    /*!
      @brief GetVersion (L4)
      @param[out] ver Version information
      @return True if successful
     */
    bool mifareGetVersion4(uint8_t ver[8]);
    ///@}

    ///@name NTAG
    ///@{
    /*!
      @brief Read between specified pages
      @param rx Receiver buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param spage Start reading page
      @param epage End reading page
      @return True if successful
      @warning Only PICC with the FAST_READ command
     */
    bool ntagReadPage(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage);
    ///@}

    // ----------------------------------------------------------------------------------------------
    ///@name NFC-B
    ///@{
    /*!
      @brief Transceive with NFC-B PICC
      @param[out] rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcbTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                        const uint32_t timeout_ms);
    /*!
      @param Transmit to NFC-B PICC
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcbTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);
    /*!
      @param Receive from NFC-B PICC
      @param[out] rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcbReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms);
    ///@}

    // ----------------------------------------------------------------------------------------------
    ///@name NFC-F
    ///@{
    /*!
      @brief Transceive with NFC-F PICC
      @param[out] rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcfTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                        const uint32_t timeout_ms);
    /*!
      @param Transmit to NFC-F PICC
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcfTransmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);
    /*!
      @param Receive from NFC-F PICC
      @param[out] rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool nfcfReceive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms);

    ///@}

    // ----------------------------------------------------------------------------------------------
    ///@name NFC-V
    ///@{
    /*!
      @brief Transceive
      @param[out] rx Receive buffer
      @param[in/out] rx_len in:Size of receive buffer out:actual read size
      @param tx Send buffer
      @param tx_len Size of send buffer
      @param timeout_ms Timeout(ms)
      @param mode ModulationMode
      @return True if successful
      @note Perform encoding/decoding for transmission and reception internally
     */
    bool nfcvTransceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_bytes,
                        const uint32_t timeout_ms,
                        const m5::nfc::v::ModulationMode mode = m5::nfc::v::ModulationMode::OneOf4);
    /*!
      @brief Check inventory slots
      @param[out] piccs Detected PICCs
      @param single Using 1 slot if true, using 16 slot if false
      @return True if successful
      @note ISO/IEC 15693-3 INVENTORY
     */
    bool nfcvInventry(std::vector<m5::nfc::v::PICC>& piccs, const bool single = true);
    /*!
      @brief Stay quiet
      @patam picc PICC
      @return True if successful
      @note ISO/IEC 15693-3 STAY QUIET
     */
    bool nfcvStayQuiet(const m5::nfc::v::PICC& picc);
    /*!
      @brief Select
      @patam picc PICC
      @return True if successful
      @note ISO/IEC 15693-3 SELECT
     */
    bool nfcvSelect(const m5::nfc::v::PICC& picc);
    /*!
      @brief Reset to ready for specific PICC
      @patam picc PICC
      @return True if successful
      @note ISO/IEC 15693-3 RESET TO READY
     */
    bool nfcvResetToReady(const m5::nfc::v::PICC& picc);
    /*!
      @brief Reset to ready for selected PICC
      @return True if successful
      @note ISO/IEC 15693-3 RESET TO READY
     */
    bool nfcvResetToReady();
    /*!
      @brief  Get system information
      @patam[in/out] picc PICC
      @return True if successful
      @note ISO/IEC 15693-3 GET SYSTEM INFORMATION
      @note The information obtained is used to update the PICC
     */
    bool nfcvGetSystemInformation(m5::nfc::v::PICC& picc);
    /*!
      @brief Read the block of the specified PICC
      @param[out] rx Output buffer (At least the size of one PICC block)
      @patam picc PICC
      @param block Block address
      @return True if successful
      @note The specified PICC status is not required
      @warning The required size varies depending on the PICC
      @warning The maximum rx size is 32
     */
    bool nfcvReadSingleBlock(uint8_t rx[32], const m5::nfc::v::PICC& picc, const uint8_t block);
    /*!
      @brief Read the block of the selected PICC
      @param[out] rx Output buffer (At least the size of one PICC block)
      @patam picc PICC
      @param block Block address
      @return True if successful
      @warning The required size varies depending on the PICC
      @warning The maximum rx size is 32
     */
    bool nfcvReadSingleBlock(uint8_t rx[32], const uint8_t block);
    /*!
      @brief Write the block of the specified PICC
      @patam picc PICC
      @param block Block address
      @param tx Input buffer
      @param tx_len Input buffer length (Same as the size of one PICC block)
      @param option Using option_flag for request if true
      @return True if successful
      @note The specified PICC status is not required
      @warning The required tx_size varies depending on the PICC
      @warning The maximum tx_len is 32
     */
    bool nfcvWriteSingleBlock(const m5::nfc::v::PICC& picc, const uint8_t block, const uint8_t* tx,
                              const uint8_t tx_len, const bool option = false);
    /*!
      @brief Write the block of the selected PICC
      @param block Block address
      @param tx Input buffer
      @param tx_len Input buffer length (Same as the size of one PICC block)
      @param option Using option_flag for request if true
      @return True if successful
      @note The specified PICC status is not required
      @warning The required tx_size varies depending on the PICC
      @warning The maximum tx_len is 32
     */
    bool nfcvWriteSingleBlock(const uint8_t block, const uint8_t* tx, const uint8_t tx_len, const bool option = false);
    ///@}

    ///@name PT_MEMORY
    ///@{
    bool writePtMemoryA(const uint8_t* tx, const uint32_t tx_len);
    bool writePtMemoryF(const uint8_t* tx, const uint32_t tx_len);
    bool writePtMemoryTSN(const uint8_t* tx, const uint32_t tx_len);
    bool readPtMemory(uint8_t* rx, const uint32_t rx_len);
    ///@}

    // For debug
    void dumpRegister();

protected:
    friend struct m5::nfc::ListenerST25R3916ForA;
    friend struct m5::nfc::ListenerST25R3916ForF;

    static void IRAM_ATTR on_irq(void* arg);

    bool read_register8(const uint8_t reg, uint8_t& v);
    bool read_register8(const uint16_t reg, uint8_t& v);
    bool write_register8(const uint8_t reg, const uint8_t v);
    bool write_register8(const uint16_t reg, const uint8_t v);
    bool read_register16(const uint8_t reg, uint16_t& v);
    bool read_register16(const uint16_t reg, uint16_t& v);
    bool write_register16(const uint8_t reg, const uint16_t v);
    bool write_register16(const uint16_t reg, const uint16_t v);
    bool read_register32(const uint8_t reg, uint32_t& v);
    bool read_register32(const uint16_t reg, uint32_t& v);
    bool write_register32(const uint8_t reg, const uint32_t v);
    bool write_register32(const uint16_t reg, const uint32_t v);

    bool write_fwt_timer(const uint32_t ms);
    bool write_mask_receiver_timer(const uint32_t us);
    bool write_squelch_timer(const uint32_t us);

    uint32_t wait_for_interrupt(const uint32_t irq, const uint32_t timeout_ms = 100);

    bool wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size = 0);
    bool read_FIFO(std::vector<uint8_t>& out);

    // Mode confifuration
    bool configure_nfc_a();
    bool configure_nfc_b();
    bool configure_nfc_f();
    bool configure_nfc_v();
    bool nfc_initial_field_on();

    bool configure_emulation_a();
    bool configure_emulation_f();

    // Utility
    bool modify_bit_register8(const uint8_t reg, const uint8_t set_mask, const uint8_t clear_mask);
    bool modify_bit_register8(const uint16_t reg, const uint8_t set_mask, const uint8_t clear_mask);
    bool set_bit_register8(const uint8_t reg, const uint8_t bits);
    bool set_bit_register8(const uint16_t reg, const uint8_t bits);
    bool clear_bit_register8(const uint8_t reg, const uint8_t bits);
    bool clear_bit_register8(const uint16_t reg, const uint8_t bits);
    inline bool change_bit_register8(const uint8_t reg, const uint8_t bits, const uint8_t mask)
    {
        return modify_bit_register8(reg, mask & bits, mask);
    }
    inline bool change_bit_register8(const uint16_t reg, const uint8_t bits, const uint8_t mask)
    {
        return modify_bit_register8(reg, mask & bits, mask);
    }
    bool change_test_bit_register8(const uint8_t reg, const uint8_t bits, const uint8_t mask);
    bool change_test_bit_register8(const uint16_t reg, const uint8_t bits, const uint8_t mask);

    bool modify_interrupts(const uint32_t clr, const uint32_t set);
    inline bool enable_interrupts(const uint32_t mask)
    {
#if 0
        if (writeMaskInterrupts(~mask)) {
            _enabled_irq |= mask;
            return true;
        }
        return false;
#else
        return modify_interrupts(mask, 0);
#endif
    }
    inline bool disable_interrupts(const uint32_t mask)
    {
#if 0
        if (writeMaskInterrupts(mask)) {
            _enabled_irq &= ~mask;
            return true;
        }
        return false;
#else
        return modify_interrupts(0, mask);
#endif
    }

    bool enable_osc();
    bool disable_field();

    // NFC-A
    bool nfca_request_wakeup(uint16_t& atqa, const bool req);
    bool nfca_anti_collision(uint8_t rbuf[5], const uint8_t lv);

    // MIFARE
    bool mifare_transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                           const uint32_t timeout_ms);
    bool mifare_classic_send_encrypt(const uint8_t* tx, const uint16_t tx_len);
    bool mifare_classic_transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                           const uint32_t timeout_ms, const bool include_crc, const bool decrypt);
    bool mifare_classic_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::PICC& picc, const uint8_t block,
                                     const m5::nfc::a::mifare::classic::Key& key);

    // NFC-V
    bool nfcv_transmit(const uint8_t* tx, const uint16_t tx_len, const m5::nfc::v::ModulationMode mode,
                       const uint32_t timeout_ms);
    bool nfcv_receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms);
    bool nfcv_reset_to_ready(const m5::nfc::v::PICC* picc);
    bool nfcv_read_single_block(uint8_t rx[32], const uint8_t req, const m5::nfc::v::PICC* picc, const uint8_t block);
    bool nfcv_write_single_block(const m5::nfc::v::PICC* picc, const uint8_t block, const uint8_t req,
                                 const uint8_t* tx, const uint8_t tx_len);

private:
    config_t _cfg{};

    volatile uint32_t _stored_irq{};
    uint32_t _enabled_irq{};  // for !_using_irq

    volatile bool _interrupt_occurred{};
    m5::nfc::NFC _nfcMode{};
    bool _encrypted{};
    bool _using_irq{};

    m5::nfc::a::mifare::classic::Crypto1 _crypto1{};
};

/*!
  @class CapST25R3916
  @brief ST25R3916 unit in HackerCap (SPI)
 */
class CapST25R3916 : public UnitST25R3916 {
    M5_UNIT_COMPONENT_HPP_BUILDER(CapST25R3916, 0x06 /* SPI CS pin */);

public:
    explicit CapST25R3916(const uint8_t cs_pin = DEFAULT_ADDRESS);
    virtual ~CapST25R3916() = default;

    virtual bool begin() override;
};

}  // namespace unit
}  // namespace m5
#endif
