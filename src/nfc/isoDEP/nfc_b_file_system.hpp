/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_b_file_system.hpp
  @brief File system base using isoDEP for NFC-B
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_ISODEP_NFC_B_FILE_SYSTEM_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_ISODEP_NFC_B_FILE_SYSTEM_HPP

#include "file_system.hpp"

namespace m5 {
namespace nfc {
class NFCLayerB;

/*!
  @class NFCBFileSystem
  @brief File system base using isoDEP for NFC-B
 */
class NFCBFileSystem : public FileSystem {
public:
    explicit NFCBFileSystem(m5::nfc::NFCLayerB& layer);
};

}  // namespace nfc
}  // namespace m5
#endif
