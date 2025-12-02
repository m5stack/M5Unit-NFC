/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc.hpp
  @brief NFC definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_NFC_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_NFC_HPP

#include <cstdint>

namespace m5 {
/*!
  @namespace nfc
  @brief NFC related definitions
 */
namespace nfc {

/*!
  @enum NFC
  @brief NFC type
 */
enum class NFC : uint8_t {
    None,  //!< No mode
    A,     //!< NFC-A
    B,     //!< NFC-B
    F,     //!< NFC-F
    V      //!< NFC-V
};

/*!
  @enum NFCForumTag
  @brief NFC Forum Tag Type
 */
enum class NFCForumTag : uint8_t {
    None,
    Type1,  //!< Type 1 (NFC-A)
    Type2,  //!< Type 2 (NFC-A)
    Type3,  //!< Type 3 (NFC-F)
    Type4,  //!< Type 4 (NFC-A, NFC-B)
    Type5,  //!< Type 5 ISO/IEC 15693
};

}  // namespace nfc
}  // namespace m5

// #include "a/nfca.hpp"
// #include "b/nfcb.hpp"
// #include "f/nfcf.hpp"
// #include "v/nfcv.hpp"
// #include "ndef/ndef.hpp"
#endif
