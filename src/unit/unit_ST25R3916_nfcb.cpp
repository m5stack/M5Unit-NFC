/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file unit_ST25R3916_nfcb.cpp
  @brief class UnitST25R3916 implementation for NFC-B
*/
#include "unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;

using namespace m5::unit::types;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::regval;
using namespace m5::unit::st25r3916::command;

using namespace m5::nfc;
using namespace m5::nfc::b;

#define CHECK_MODE()                                   \
    do {                                               \
        if (!isNFCMode(NFC::B)) {                      \
            M5_LIB_LOGE("Illegal mode %u", NFCMode()); \
            return false;                              \
        }                                              \
    } while (0)

namespace {
}  // namespace

namespace m5 {
namespace unit {
// -------------------------------- For NFC-B
bool UnitST25R3916::configure_nfc_b()
{
    M5_LIB_LOGE("Not yet");
    return false;
}

}  // namespace unit
}  // namespace m5
