/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916.hpp
  @brief ST25R3916 Unit for M5UnitUnified
*/
#ifndef M5_UNIT_RFID_UNIT_ST25R3916_HPP
#define M5_UNIT_RFID_UNIT_ST25R3916_HPP

#include <M5UnitComponent.hpp>
#include "ST25R3916_definition.hpp"
#include "nfc/nfc.hpp"
#include "nfc/a/mifare_crypto1.hpp"

namespace m5 {
namespace unit {
namespace nfc {
struct AdapterST25R3916;
}

/*!
  @class UnitST25R3916
  @brief ST25R3916 Unit
 */
class UnitST25R3916 : public Component {
    M5_UNIT_COMPONENT_HPP_BUILDER(UnitST25R3916, 0x50 /* I2C address */);
    friend struct m5::unit::nfc::AdapterST25R3916;

public:
    explicit UnitST25R3916(const uint8_t arg = DEFAULT_ADDRESS) : Component(arg)
    {
    }
    virtual ~UnitST25R3916() = default;

    virtual bool begin() override;
    virtual void update(const bool force = false) override;

    /*!
      @struct config_t
      @brief Settings for begin
     */
    struct config_t {
        bool vdd_voltage_5V{false};    //!< VDD voltage true:5V false:3.3V
        uint8_t tx_am_modulation{13};  // 0-15 See also 4.5.48 TX driver register
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
    //  "interrupts" is defined as a macro in Arduino.h...
    //! @brief Get interrupts flag
    inline uint32_t irq_flags() const
    {
        return _irq_flags;
    }
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

    bool writeBitrate(const st25r3916::Bitrate tx, const st25r3916::Bitrate rx);
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
      @return True if successful
     */
    bool readFIFO(uint16_t& actual, uint8_t* buf, const uint16_t buf_size);
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
    inline bool readNFCIP1Definition(uint8_t& value)
    {
        return read_register8(st25r3916::command::REG_NFCIP_1_DEFINITION, value);
    }
    /*!
      Write the NFCIP-1 passive target definition
      @param[out] value Value
      @return True if successful
     */
    inline bool writeFCIP1Definition(const uint8_t value)
    {
        return write_register8(st25r3916::command::REG_NFCIP_1_DEFINITION, value);
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
    inline bool writeP2PReceiverConfiguration(uint8_t& value)
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
    inline bool writeCorrelatorConfiguration1(uint8_t& value)
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
    inline bool writeCorrelatorConfiguration2(uint8_t& value)
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
    inline bool writeCorrelatorConfiguration(uint16_t& value)
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
    inline bool writeSquelchTimer(uint8_t& value)
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
    inline bool writeNFCFieldOnGuardTimer(uint8_t& value)
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
    inline bool writeMaskMainInterrupt(const uint8_t& value)
    {
        return write_register8(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value);
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
    inline bool writeMaskTimerAndNFCInterrupt(const uint8_t& value)
    {
        return write_register8(st25r3916::command::REG_MASK_TIMER_AND_NFC_INTERRUPT, value);
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
    inline bool writeMaskErrorAndWakeupInterrupt(const uint8_t& value)
    {
        return write_register8(st25r3916::command::REG_MASK_ERROR_AND_WAKEUP_INTERRUPT, value);
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
    inline bool writeMaskPassiveTargetInterrupt(const uint8_t& value)
    {
        return write_register8(st25r3916::command::REG_MASK_PASSIVE_TARGET_INTERRUPT, value);
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
        return write_register32(st25r3916::command::REG_MASK_MAIN_INTERRUPT, value);
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
    inline bool wrtePassiveTargetModulation(const uint8_t value)
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

    bool hltA();

    bool dump(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY);

    bool mifareAuthenticateA(const m5::nfc::a::UID& uid, const uint8_t sblock,
                             const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY);
    bool mifare_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::UID& uid, const uint8_t block,
                             const m5::nfc::a::mifare::Key& key);

    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::Key& key);

protected:
    bool read_register8(const uint8_t reg, uint8_t& v);
    bool read_register8(const uint16_t reg, uint8_t& v);
    bool write_register8(const uint8_t reg, const uint8_t v);
    bool write_register8(const uint16_t reg, const uint8_t v);
    bool set_bit_register8(const uint8_t reg, const uint8_t bitss);
    bool set_bit_register8(const uint16_t reg, const uint8_t bitss);
    bool clear_bit_register8(const uint8_t reg, const uint8_t clear_bitss);
    bool clear_bit_register8(const uint16_t reg, const uint8_t clear_bitss);

    // BEg
    bool read_register16(const uint8_t reg, uint16_t& v);
    bool read_register16(const uint16_t reg, uint16_t& v);
    bool write_register16(const uint8_t reg, const uint16_t v);
    bool write_register16(const uint16_t reg, const uint16_t v);

    bool read_register32(const uint8_t reg, uint32_t& v);
    bool read_register32(const uint16_t reg, uint32_t& v);
    bool write_register32(const uint8_t reg, const uint32_t v);
    bool write_register32(const uint16_t reg, const uint32_t v);

    bool read_FIFO(std::vector<uint8_t>& out);

    uint32_t wait_for_interrupt(const uint32_t irq, const uint32_t timeout_ms = 100, const bool include_error = true);
    inline uint32_t wait_for_interrupt(const uint8_t main, const uint8_t timer, const uint8_t error,
                                       const uint8_t passive, const uint32_t timeout_ms = 100)
    {
        return wait_for_interrupt(((uint32_t)main << 24) | ((uint32_t)timer << 16) | ((uint8_t)error << 8) | passive,
                                  timeout_ms);
    }
    bool wait_for_FIFO(const uint32_t timeout_ms, const uint16_t required_size = 0);

    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                    const uint32_t timeout_ms = 0);

    bool transceive_encrypt(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms = 0);

    bool read_block(uint8_t* rx, uint16_t& rx_len, const uint8_t addr);
    bool ntag_fast_read(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage);
    bool ntag_dump_all(const uint8_t maxPage);
    bool ntag_dump_page(const uint8_t page);

    bool req_wup_device(uint16_t& atqa, const bool req);

    bool anti_collision(uint8_t rbuf[5], const uint8_t lv);
    bool select_with_anticollision(bool& completed, m5::nfc::a::UID& uid, const uint8_t lv);
    bool select(const m5::nfc::a::UID& uid);

    m5::nfc::a::Type identify_mifare_type(const m5::nfc::a::UID& uid);
    bool get_version(uint8_t info[10]);

    bool dump_sector(const uint8_t sector);

    bool write_noresponse_timeout(const uint32_t ms);

    static void IRAM_ATTR on_irq(void* arg);

private:
    config_t _cfg{};
    volatile bool _interrupt_occurred{};
    uint32_t _irq_flags{};
    MifareCrypto1 _crypto1{};
};

/*!
  @class CapST25R3916
  @brief ST25R3916 unit in HackerCap (SPI)
 */
class CapST25R3916 : public UnitST25R3916 {
    M5_UNIT_COMPONENT_HPP_BUILDER(CapST25R3916, 0x06 /* SPI CS pin */);

public:
    explicit CapST25R3916(const uint8_t cs_pin = DEFAULT_ADDRESS) : UnitST25R3916(cs_pin)
    {
    }
    virtual ~CapST25R3916() = default;

    virtual bool begin() override;

protected:
};

}  // namespace unit
}  // namespace m5
#endif
