/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file M5UnitUnifiedNFC.hpp
  @brief Main header of M5Unit-NFC

  @mainpage M5Unit-NFC
  Library for Unit-NFC using M5UnitUnified.
  Include NFC-x related definitions.
*/
#ifndef M5_UNIT_UNIFIED_NFC_HPP
#define M5_UNIT_UNIFIED_NFC_HPP

#include "nfc/nfc.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include "nfc/ndef/ndef_record.hpp"

#include "unit/unit_ST25R3916.hpp"

#include "nfc/layer/nfc_layer_a.hpp"
#include "nfc/layer/nfc_layer_f.hpp"

/*!
  @namespace m5
  @brief Top level namespace of M5stack
 */
namespace m5 {
/*!
  @namespace unit
  @brief Unit-related namespace
 */
namespace unit {

using UnitNFC      = m5::unit::UnitST25R3916;
using HackerCapNFC = m5::unit::CapST25R3916;

}  // namespace unit
}  // namespace m5
#endif
