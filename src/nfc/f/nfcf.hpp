/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcf.hpp
  @brief NFC-F definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_F_NFCF_HPP

#include <cstdint>

namespace m5 {
namespace nfc {
/*!
  @namespace f
  @brief NFC-F definitions
 */
namespace f {

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type
};

/*!
  @struct IDm
  @brief The Idm(Identifier for Manufacturer) of the PICC
 */
struct IDm {
    //! @brief uid data
    uint8_t uid[8]{};
};

}  // namespace f
}  // namespace nfc
}  // namespace m5
#endif
