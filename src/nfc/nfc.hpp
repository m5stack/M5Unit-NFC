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
#include "a/nfca.hpp"
#include "b/nfcb.hpp"
#include "f/nfcf.hpp"
#include "v/nfcv.hpp"
#include "ndef/ndef.hpp"

namespace m5 {
/*!
  @namespace nfc
  @brief NFC related definitions
 */
namespace nfc {

/*!
  @enum NFC
  @brief Operation Mode
 */
enum class NFC : uint8_t {
    None,  //!< No mode
    A,     //!< NFC-A
    B,     //!< NFC-B
    F,     //!< NFC-F
    V      //!< NFC-V
};

}  // namespace nfc
}  // namespace m5

#endif
