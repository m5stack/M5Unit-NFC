/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file desfire_file_system.hpp
  @brief File system base using isoDEP for MIFARE DESFire
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_ISODEP_DESFIRE_FILE_SYSTEM_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_ISODEP_DESFIRE_FILE_SYSTEM_HPP
#include "file_system.hpp"

namespace m5 {
namespace nfc {
namespace mifare {
class DESFireFileSystem : public FileSystem {
public:
    explicit DESFireFileSystem(m5::nfc::isodep::IsoDEP& isoDEP) : FileSystem(isoDEP)
    {
    }
};
}  // namespace mifare
}  // namespace nfc
}  // namespace m5
#endif
