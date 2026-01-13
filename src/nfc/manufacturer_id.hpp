/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file manufacturer_id.hpp
  @brief Manufacturer ID (UID[0]) definitions for ISO/IEC 14443-3
  @note Manufacturer ID values are aligned with ISO/IEC 7816-6 manufacturer codes
 */
#ifndef M5_UNIT_NFC_NFC_MANUFACTURER_ID_HPP
#define M5_UNIT_NFC_NFC_MANUFACTURER_ID_HPP

#include <cstdint>

namespace m5 {
namespace nfc {

/*!
  @enum ManufacturerId
  @brief Manufacturer ID derived from UID[0]
  @note This list is partial,extend as needed
  @warning Random UID may not reflect actual manufacturer
 */
enum class ManufacturerId : uint8_t {
    Unknown            = 0x00,  //!< Unknown/unsupported
    Motorola           = 0x01,  //!< Motorola
    STMicroelectronics = 0x02,  //!< STMicroelectronics
    Hitachi            = 0x03,  //!< Hitachi
    NXP                = 0x04,  //!< NXP Semiconductors
    Infineon           = 0x05,  //!< Infineon
    Cylink             = 0x06,  //!< Cylink
    TexasInstruments   = 0x07,  //!< Texas Instruments
    Fujitsu            = 0x08,  //!< Fujitsu
    Matsushita         = 0x09,  //!< Matsushita (Panasonic)
    NEC                = 0x0A,  //!< NEC
    Oki                = 0x0B,  //!< Oki
    Toshiba            = 0x0C,  //!< Toshiba
    Mitsubishi         = 0x0D,  //!< Mitsubishi
    MultibyteMarker    = 0xFF,  //!< ISO/IEC 7816-6:2023
};

}  // namespace nfc
}  // namespace m5

#endif
