/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfcv.hpp
  @brief NFC-V definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_V_NFCV_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_V_NFCV_HPP

#include <cstdint>

namespace m5 {
namespace nfc {
/*!
  @namespace v
  @brief NFC-V definitions
 */
namespace v {

/*!
  @enum Type
  @brief Type of the PICC
 */
enum class Type : uint8_t {
    Unknown,  //!< Unknown type
};

/*!
  @struct UID
  @brief The UID of the PICC
 */
struct UID {
    //! @brief uid data
    uint8_t uid[8]{};
};

}  // namespace v
}  // namespace nfc
}  // namespace m5
#endif
