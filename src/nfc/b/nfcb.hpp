/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcb.hpp
  @brief NFC-B definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_B_NFCB_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_B_NFCB_HPP

#include <cstdint>

namespace m5 {
namespace nfc {
/*!
  @namespace b
  @brief NFC-B definitions
 */
namespace b {

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type
};

/*!
  @struct PUPI
  @brief The PUPI(Pseudo-Unique PICC Identifier) of the PICC
 */
struct PUPI {
    //! @brief uid data
    uint8_t uid[8]{};
};

}  // namespace b
}  // namespace nfc
}  // namespace m5
#endif
