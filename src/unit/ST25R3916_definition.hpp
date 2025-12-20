/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ST25R3916_definition.hpp
  @brief Definitions for ST25R3916
*/
#ifndef M5_UNIT_NFC_ST25R3916_DEFINITION_HPP
#define M5_UNIT_NFC_ST25R3916_DEFINITION_HPP

#include <cstdint>

namespace m5 {
namespace unit {

/*!
  @namespace st25r3916
  @brief For ST25R3916
 */
namespace st25r3916 {

/*!
  @enum InitiatorOperationMode
  @brief Initiator operation modes
  @details For Mode definition
 */
enum class InitiatorOperationMode : uint8_t {
    NFCIP1           = 0x00 << 3,  //!< NFCIP-1 active communication
    ISO14443A        = 0x01 << 3,  //!< ISO14443A
    ISO14443B        = 0x02 << 3,  //!< ISO14443B
    FeliCa           = 0x03 << 3,  //!< FeliCa
    NFCForumType1    = 0x04 << 3,  //!< NFC Forum Type 1 tag (Topaz)
    SubCarrierStream = 0x0E << 3,  //!< Sub-carrier stream mode
    BPSKStream       = 0x0F << 3,  //!< BPSK stream mode
};

/*!
  @enum TargetOperationMode
  @brief Target operation modes
  @details For Mode definition
 */
enum class TargetOperationMode : uint8_t {
    ISO14443A        = 0x01 << 3,  //!< ISO14443A passive target mode
    Felica           = 0x04 << 3,  //!< FeliCa™ passive target mode
    NFCIP1           = 0x07 << 3,  //!< NFCIP-1 active communication mode
    FelicaBitrate    = 0x0C << 3,  //!< FeliCa bit rate detection mode
    ISO14443ABitrate = 0x09 << 3,  //!< ISO14443A bit rate detection mode
    //    BothBitrate = 0x0D << 3, //!< Felica and ISO14443A bit rate detection mode
};

///@name PT_MEMORY
///@{
constexpr uint32_t PT_MEMORY_A_LENGTH{15};    //!< A-config length
constexpr uint32_t PT_MEMORY_F_LENGTH{21};    //!< F-config length
constexpr uint32_t PT_MEMORY_TSN_LENGTH{12};  //!< TSN data length
constexpr uint32_t PT_MEMORY_LENGTH{PT_MEMORY_A_LENGTH + PT_MEMORY_F_LENGTH + PT_MEMORY_TSN_LENGTH};  //!< all length
///@}

namespace command {
///@cond
// ==== Space-A
// I/O configuration
constexpr uint8_t REG_IO_CONFIGURATION_1{0x00};
constexpr uint8_t REG_IO_CONFIGURATION_2{0x01};
// Operation control and mode definition
constexpr uint8_t REG_OPERATION_CONTROL{0x02};
constexpr uint8_t REG_MODE_DEFINITION{0x03};
constexpr uint8_t REG_BITRATE_DEFINITION{0x04};
// Protocol configuration
constexpr uint8_t REG_ISO14443A_SETTINGS{0x05};
constexpr uint8_t REG_ISO14443B_SETTINGS{0x06};
constexpr uint8_t REG_FELICA_SETTINGS{0x07};
constexpr uint8_t REG_NFCIP_1_PASSIVE_TARGET_DEFINITION{0x08};
constexpr uint8_t REG_STREAM_MODE_DEFINITION{0x09};
constexpr uint8_t REG_AUXILIARY_DEFINITION{0x0A};
// Receiver configuration
constexpr uint8_t REG_RECEIVER_CONFIGURATION_1{0x0B};
constexpr uint8_t REG_RECEIVER_CONFIGURATION_2{0x0C};
constexpr uint8_t REG_RECEIVER_CONFIGURATION_3{0x0D};
constexpr uint8_t REG_RECEIVER_CONFIGURATION_4{0x0E};
// Timer definition
constexpr uint8_t REG_MASK_RECEIVER_TIMER{0x0F};
constexpr uint8_t REG_NO_RESPONSE_TIMER_1{0x10};
constexpr uint8_t REG_NO_RESPONSE_TIMER_2{0x11};
constexpr uint8_t REG_TIMER_AND_EMV_CONTROL{0x12};
constexpr uint8_t REG_GENERAL_PURPOSE_TIMER_1{0x13};
constexpr uint8_t REG_GENERAL_PURPOSE_TIMER_2{0x14};
constexpr uint8_t REG_PPON2_FIELD_WAITING{0x15};
// Interrupt and associated reporting
constexpr uint8_t REG_MASK_MAIN_INTERRUPT{0x16};
constexpr uint8_t REG_MASK_TIMER_AND_NFC_INTERRUPT{0x17};
constexpr uint8_t REG_MASK_ERROR_AND_WAKEUP_INTERRUPT{0x18};
constexpr uint8_t REG_MASK_PASSIVE_TARGET_INTERRUPT{0x19};
constexpr uint8_t REG_MAIN_INTERRUPT{0x1A};
constexpr uint8_t REG_TIMER_AND_NFC_INTERRUPT{0x1B};
constexpr uint8_t REG_ERROR_AND_WAKEUP_INTERRUPT{0x1C};
constexpr uint8_t REG_PASSIVE_TARGET_INTERRUPT{0x1D};
constexpr uint8_t REG_FIFO_STATUS_1{0x1E};
constexpr uint8_t REG_FIFO_STATUS_2{0x1F};
constexpr uint8_t REG_COLLISION_DISPLAY{0x20};
constexpr uint8_t REG_PASSIVE_TARGET_DISPLAY{0x21};
// Definition of number of transmitted bytes
constexpr uint8_t REG_NUMBER_OF_TRANSMITTED_BYTES_1{0x22};
constexpr uint8_t REG_NUMBER_OF_TRANSMITTED_BYTES_2{0x23};
constexpr uint8_t REG_BITRATE_DETECTION_DISPLAY{0x24};
// A/D converter output
constexpr uint8_t REG_AD_CONVERTER_OUTPUT{0x25};
// Antenna calibration
constexpr uint8_t REG_ANTENNA_TUNING_CONTROL_1{0x26};
constexpr uint8_t REG_ANTENNA_TUNING_CONTROL_2{0x27};
// Antenna driver and modulation
constexpr uint8_t REG_TX_DRIVER{0x28};
constexpr uint8_t REG_PASSIVE_TARGET_MODULATION{0x29};
// External field detector threshold
constexpr uint8_t REG_EXTERNAL_FIELD_DETECTOR_ACTIVATION_THRESHOLD{0x2A};
constexpr uint8_t REG_EXTERNAL_FIELD_DETECTOR_DEACTIVATION_THRESHOLD{0x2B};
// Regulator
constexpr uint8_t REG_REGULATOR_VOLTAGE_CONTROL{0x2C};
// Receiver state display
constexpr uint8_t REG_RSSI_DISPLAY{0x2D};
constexpr uint8_t REG_GAIN_REDUCTION_STATE{0x2E};
// Capacitive sensor
constexpr uint8_t REG_CAPACITIVE_SENSOR_CONTROL{0x2F};
constexpr uint8_t REG_CAPACITIVE_SENSOR_DISPLAY{0x30};
// Auxiliary display
constexpr uint8_t REG_AUXILIARY_DISPLAY{0x31};
// Wake-up
constexpr uint8_t REG_WAKEUP_TIMER_CONTROL{0x32};
constexpr uint8_t REG_AMPLITUDE_MEASUREMENT_CONFIGURATION{0x33};
constexpr uint8_t REG_AMPLITUDE_MEASUREMENT_REFERENCE{0x34};
constexpr uint8_t REG_AMPLITUDE_MEASUREMENT_AUTO_AVERAGING_DISPLAY{0x35};
constexpr uint8_t REG_AMPLITUDE_MEASUREMENT_DISPLAY{0x36};
constexpr uint8_t REG_PHASE_MEASUREMENT_CONFIGURATION{0x37};
constexpr uint8_t REG_PHASE_MEASUREMENT_REFERENCE{0x38};
constexpr uint8_t REG_PHASE_MEASUREMENT_AUTO_AVERAGING_DISPLAY{0x39};
constexpr uint8_t REG_PHASE_MEASUREMENT_DISPLAY{0x3A};
constexpr uint8_t REG_CAPACITANCE_MEASUREMENT_CONFIGURATION{0x3B};
constexpr uint8_t REG_CAPACITANCE_MEASUREMENT_REFERENCE{0x3C};
constexpr uint8_t REG_CAPACITANCE_MEASUREMENT_AUTO_AVERAGING_DISPLAY{0x3D};
constexpr uint8_t REG_CAPACITANCE_MEASUREMENT_DISPLAY{0x3E};
// IC identity
constexpr uint8_t REG_IC_IDENTITY{0x3F};

// ==== Space-B
// Protocol configuration
constexpr uint16_t REG_EMD_SUPPRESSION_CONFIGURATION{0x0005};
constexpr uint16_t REG_SUBCARRIER_START_TIMER{0x0006};
// Receiver configuration
constexpr uint16_t REG_P2P_RECEIVER_CONFIGURATION{0x000B};
constexpr uint16_t REG_CORRELATOR_CONFIGURATION_1{0x000C};
constexpr uint16_t REG_CORRELATOR_CONFIGURATION_2{0x000D};
// Timer definition
constexpr uint16_t REG_SQUELCH_TIMER{0x000F};
constexpr uint16_t REG_NFC_FIELD_ON_GUARD_TIMER{0x0015};
// Antenna driver and modulation
constexpr uint16_t REG_AUXILIARY_MODULATION_SETTING{0x0028};
constexpr uint16_t REG_TX_DRIVER_TIMING{0x0029};
// External field detector threshold
constexpr uint16_t REG_RESISTIVE_AM_MODULATION{0x002A};
constexpr uint16_t REG_TX_DRIVER_TIMING_DISPLAY{0x002B};
// Regulator
constexpr uint16_t REG_REGULATOR_DISPLAY{0x002C};
// Protection
constexpr uint16_t REG_OVERSHOOT_PROTECTION_CONFIGURATION_1{0x0030};
constexpr uint16_t REG_OVERSHOOT_PROTECTION_CONFIGURATION_2{0x0031};
constexpr uint16_t REG_UNDERSHOOT_PROTECTION_CONFIGURATION_1{0x0032};
constexpr uint16_t REG_UNDERSHOOT_PROTECTION_CONFIGURATION_2{0x0033};

// ==== Direct commands
constexpr uint8_t CMD_SET_DEFAULT{0xC1};            // Puts the ST25R3916/7 into powerup state
constexpr uint8_t CMD_STOP_ALL_ACTIVITIES{0xC2};    // Stops all activities
constexpr uint8_t CMD_TRANSMIT_WITH_CRC{0xC4};      // Starts a transmit sequence with automatic CRC generation
constexpr uint8_t CMD_TRANSMIT_WITHOUT_CRC{0xC5};   // Starts a transmit sequence without automatic CRC generation
constexpr uint8_t CMD_TRANSMIT_REQA{0xC6};          // Transmits REQA command (ISO14443A only)
constexpr uint8_t CMD_TRANSMIT_WUPA{0xC7};          // Transmits WUPA command (ISO14443A only)
constexpr uint8_t CMD_NFC_INITIAL_FIELD_ON{0xC8};   // Performs Initial RF Collision avoidance and switches on the field
constexpr uint8_t CMD_NFC_RESPONSE_FIELD_ON{0xC9};  // Performs Response
                                                    // RF Collision avoidance and switches on the field
constexpr uint8_t CMD_GO_TO_SENSE{0xCD};            // Puts the passive target logic into Sense (Idle) state
constexpr uint8_t CMD_GO_TO_SLEEP{0xCE};            // Puts the passive target logic into Sleep (Halt) state
constexpr uint8_t CMD_MASK_RECEIVE_DATA{0xD0};      // Stops receivers and RX decoders
constexpr uint8_t CMD_UNMASK_RECEIVE_DATA{0xD1};    // Starts receivers and RX decoders
constexpr uint8_t CMD_CHANGE_AM_MODULATION_STATE{0xD2};  // Changes AM modulation state
constexpr uint8_t CMD_MEASURE_AMPLITUDE{0xD3};           // Measures the amplitude of the signal present on RFI inputs
constexpr uint8_t CMD_RESET_RX_GAIN{0xD5};               // Resets receiver gain
constexpr uint8_t CMD_ADJUST_REGULATORS{0xD6};           // Adjusts supply regulators according
                                                         // to the current supply voltage level
constexpr uint8_t CMD_CALIBRATE_DRIVER_TIMING{0xD8};     // Starts the driver timing calibration
constexpr uint8_t CMD_MEASURE_PHASE{0xD9};           // Measures the phase difference between the signal on RFO and RFI
constexpr uint8_t CMD_CLEAR_RSSI{0xDA};              // Clears the RSSI bits and restarts the measurement
constexpr uint8_t CMD_CLEAR_FIFO{0xDB};              // Clears FIFO
constexpr uint8_t CMD_ENTER_TRANSPARENT_MODE{0xDC};  // Enters in Transparent mode
constexpr uint8_t CMD_CALIBRATE_CAPACITIVE_SENSOR{0xDD};  // Calibrates capacitive sensor
constexpr uint8_t CMD_MEASURE_CAPACITANCE{0xDE};          // Measures capacitance between CSO and CSI pin
constexpr uint8_t CMD_MEASURE_POWER_SUPPLY{0xDF};         //
constexpr uint8_t CMD_START_GENERAL_PURPOSE_TIMER{0xE0};  //
constexpr uint8_t CMD_START_WAKEUP_TIMER{0xE1};           //
constexpr uint8_t CMD_START_MASK_RECEIVE_TIMER{0xE2};     // Starts the mask-receive timer and squelch operation
constexpr uint8_t CMD_Start_NO_RESPONSE_TIMER{0xE3};      //
constexpr uint8_t CMD_START_PPON2_TIMER{0xE4};            //
constexpr uint8_t CMD_STOP_NO_RESPONSE_TIMER{0xE5};       //
constexpr uint8_t CMD_REGISTER_SPACEB_ACCESS{0xFB};       // Enables R/W access to register Space-B
constexpr uint8_t CMD_TEST_ACCESS{0xFC};                  // Enable R/W access to Test register
///@endcond
}  // namespace command

constexpr uint8_t VALID_IDENTIFY_TYPE{0x05};  // 00000101b (ST25R3916/7)
constexpr uint16_t MAX_FIFO_DEPTH{512};       //!< Maximum FIFO depth
constexpr uint16_t PREFIX_SPACE_B{(uint16_t)command::CMD_REGISTER_SPACEB_ACCESS << 8};

// Operation modes
constexpr uint8_t OP_TRAILER_MASK{0x3F};             // 00111111b
constexpr uint8_t OP_WRITE_REGISTER{0x00};           // 00xxxxxxb
constexpr uint8_t OP_READ_REGISTER{0x40};            // 01xxxxxxb
constexpr uint8_t OP_LOAD_FIFO{0x80};                // 10000000b
constexpr uint8_t OP_LOAD_PT_MEMORY_A_CONFIG{0xA0};  // 10100000b
constexpr uint8_t OP_LOAD_PT_MEMORY_F_CONFIG{0xA8};  // 10101000b
constexpr uint8_t OP_LOAD_PT_MEMORY_TSN_DATA{0xAC};  // 10101100b
constexpr uint8_t OP_READ_PT_MEMORY{0xBF};           // 10111111b
constexpr uint8_t OP_READ_FIFO{0x9F};                // 10011111b
constexpr uint8_t OP_DIRECT_COMMAND{0xC0};           // 11xxxxxxb;

/*!
  @namespace regval
  @brief Register setting value
 */
namespace regval {
///@cond
// 0x00 IO configuration register 1
constexpr uint8_t i2c_thd1{0x20};
constexpr uint8_t i2c_thd0{0x10};

constexpr uint16_t i2c_thd116{0x2000};
constexpr uint16_t i2c_thd016{0x1000};

// 0x01 IO configuration register 2
constexpr uint8_t sup3v{0x80};
constexpr uint8_t aat_en{0x20};
constexpr uint8_t io_drv_lvl{0x04};
constexpr uint8_t miso_pd1{0x08};
constexpr uint8_t miso_pd2{0x10};

// 0x02 Operation control register
constexpr uint8_t en{0x80};     // 1: Enables oscillator and regulator(Ready mode)
constexpr uint8_t rx_en{0x40};  // 1: Enables Rx operation
constexpr uint8_t tx_en{0x08};  // 1: Enables Tx operation
constexpr uint8_t wu{0x04};     // 1: Enables Wake-up mode
constexpr uint8_t en_fd_c1{0x02};
constexpr uint8_t en_fd_c0{0x01};

constexpr uint8_t en_fd_mask{0x03};
constexpr uint8_t en_fd_off{0x00};
constexpr uint8_t en_fd_manual_ca{0x01};
constexpr uint8_t en_fd_manual_pdt{0x02};
constexpr uint8_t en_fd_manual_auto{0x03};

// 0x03 Mode definition register
constexpr uint8_t targ{0x80};  // 0: Initiator 1: Target
constexpr uint8_t tr_am{0x04};
constexpr uint8_t nfc_ar0{0x01};
constexpr uint8_t nfc_ar1{0x02};

constexpr uint8_t nfc_ar8_off{0x00};
constexpr uint8_t nfc_ar8_auto{0x01};
constexpr uint8_t nfc_ar8_always{0x02};
constexpr uint8_t nfc_ar8_RFI{0x03};

// 0x05 ISO14443A and NFC 106kb/s settings register
constexpr uint8_t no_tx_par{0x80};
constexpr uint8_t no_rx_par{0x40};
constexpr uint8_t nfc_f0{0x20};
constexpr uint8_t antcl{0x01};

// 0x08 NFCIP-1 passive target definition register
constexpr uint8_t d_ac_ap2p{0x08};
constexpr uint8_t d_212_424_1r{0x04};
constexpr uint8_t d_106_ac_a{0x01};

// 0x0A Auxiliary definition register
constexpr uint8_t no_crc_rx{0x80};
constexpr uint8_t nfc_n1{0x02};
constexpr uint8_t nfc_n0{0x01};

constexpr uint8_t nfc_n_mask{0x03};

// 0x12 Timer and EMV control register
constexpr uint8_t mrt_step{0x08};  // Mask receive timer step size 0:64/fc, 1:5126/fc
constexpr uint8_t nrt_nfc{0x01};   // No-response timer start condition in AP2P initiator and target mode.
constexpr uint8_t nrt_emv{0x01};   // 1: No-response timer EMV mode
constexpr uint8_t nrt_step{0x01};  // No-response timer step size 0:64/fc, 1:4096/fc

// 0x1A Main interrupt register
constexpr uint8_t I_osc{0x80};      // IRQ when oscillator frequency is stable
constexpr uint8_t I_wl{0x40};       // IRQ due to FIFO water level
constexpr uint8_t I_rxs{0x20};      // IRQ due to start of receive
constexpr uint8_t I_rxe{0x10};      // IRQ due to end of receive
constexpr uint8_t I_txe{0x08};      // IRQ due to end of transmission
constexpr uint8_t I_col{0x04};      // IRQ due to bit collision
constexpr uint8_t I_rx_rest{0x02};  // 1: Mask IRQ due to automatic reception restart

constexpr uint32_t I_osc32     = ((uint32_t)I_osc << 24);
constexpr uint32_t I_wl32      = ((uint32_t)I_wl << 24);
constexpr uint32_t I_rxs32     = ((uint32_t)I_rxs << 24);
constexpr uint32_t I_rxe32     = ((uint32_t)I_rxe << 24);
constexpr uint32_t I_txe32     = ((uint32_t)I_txe << 24);
constexpr uint32_t I_col32     = ((uint32_t)I_col << 24);
constexpr uint32_t I_rx_rest32 = ((uint32_t)I_rx_rest << 24);

// 0x1B Timer and NFC interrupt register
constexpr uint8_t I_dct{0x80};   // IRQ due to termination of direct command
constexpr uint8_t I_nre{0x40};   // IRQ due to No-response timer expire
constexpr uint8_t I_gpe{0x20};   // IRQ due to general purpose timer expire
constexpr uint8_t I_eon{0x10};   // IRQ due to detection of external field
constexpr uint8_t I_eof{0x08};   // IRQ due to detection of external field drop
constexpr uint8_t I_cac{0x04};   // IRQ due to detection of collision during RF collision avoidance
constexpr uint8_t I_cat{0x02};   // IRQ after minimum guard time expire
constexpr uint8_t I_nfct{0x01};  // IRQ when in target mode the initiator bit rate was recognized

constexpr uint32_t I_nre32  = ((uint32_t)I_nre << 16);
constexpr uint32_t I_eon32  = ((uint32_t)I_eon << 16);
constexpr uint32_t I_eof32  = ((uint32_t)I_eof << 16);
constexpr uint32_t I_cac32  = ((uint32_t)I_cac << 16);
constexpr uint32_t I_cat32  = ((uint32_t)I_cat << 16);
constexpr uint32_t I_nfct32 = ((uint32_t)I_nfct << 16);

// 0x1C Error and wake-up interrupt register
constexpr uint8_t I_crc{0x80};
constexpr uint8_t I_par{0x40};
constexpr uint8_t I_err2{0x20};
constexpr uint8_t I_err1{0x10};
constexpr uint8_t I_wt{0x08};
constexpr uint8_t I_wam{0x04};
constexpr uint8_t I_wph{0x02};
constexpr uint8_t I_wcap{0x01};

constexpr uint32_t I_crc32  = ((uint32_t)I_crc << 8);
constexpr uint32_t I_par32  = ((uint32_t)I_par << 8);
constexpr uint32_t I_err232 = ((uint32_t)I_err2 << 8);
constexpr uint32_t I_err132 = ((uint32_t)I_err1 << 8);

// 0x1D Passive target interrupt register
constexpr uint8_t I_ppon2{0x80};    // PPON2 field on waiting timer interrupt
constexpr uint8_t I_sl_wl{0x40};    // IRQ for passive target slot number water level
constexpr uint8_t I_apon{0x20};     // IRQ due to active P2P field on event
constexpr uint8_t I_rxe_pta{0x10};  // IRQ due to end of receive
constexpr uint8_t I_wu_f{0x08};     // NFC 212/424kb/s passive target Active interrupt
constexpr uint8_t I_wu_ax{0x02};    // Passive target Active* interrupt
constexpr uint8_t I_wu_a{0x01};     // Passive target Active interrupt

constexpr uint32_t I_apon32    = I_apon;
constexpr uint32_t I_rxe_pta32 = I_rxe_pta;
constexpr uint32_t I_wu_f32    = I_wu_f;
constexpr uint32_t I_wu_ax32   = I_wu_ax;
constexpr uint32_t I_wu_a32    = I_wu_a;

// 0x21 Passive target display register
constexpr uint8_t pta_state_power_off{0x00};
constexpr uint8_t pta_state_idle{0x01};
constexpr uint8_t pta_state_ready_l1{0x02};
constexpr uint8_t pta_state_ready_l2{0x03};
constexpr uint8_t pta_state_active{0x05};
constexpr uint8_t pta_state_halt{0x09};
constexpr uint8_t pta_state_ready_l1_x{0x0A};
constexpr uint8_t pta_state_ready_l2_x{0x0B};
constexpr uint8_t pta_state_active_x{0x0D};

// 0x31 Auxiliary display register
constexpr uint8_t a_cha{0x80};
constexpr uint8_t efd_o{0x40};
constexpr uint8_t tx_on{0x20};
constexpr uint8_t osc_ok{0x10};
constexpr uint8_t rx_on{0x08};
constexpr uint8_t rx_act{0x40};
constexpr uint8_t en_peer{0x02};
constexpr uint8_t en_ac{0x01};

///@endcond
}  // namespace regval

inline bool has_irq32_error(const uint32_t irq32)
{
    return irq32 & 0x0000FF00;
}

inline bool is_irq32_timeout(const uint32_t irq32)
{
    return irq32 & regval::I_nre32;
}

inline bool is_irq32_rxe(const uint32_t irq32)
{
    return irq32 & regval::I_rxe32;
}

inline bool is_irq32_rxs(const uint32_t irq32)
{
    return irq32 & regval::I_rxs32;
}

inline bool is_irq32_txe(const uint32_t irq32)
{
    return irq32 & regval::I_txe32;
}

inline bool is_irq32_collision(const uint32_t irq32)
{
    return irq32 & regval::I_col32;
}

uint8_t calculate_mrt(const uint32_t us, const bool mrt_step /* false:64, true:512*/);
uint16_t calculate_nrt(const uint32_t ms, const bool nrt_step /* false:64, true:4096*/);

}  // namespace st25r3916

}  // namespace unit
}  // namespace m5
#endif
