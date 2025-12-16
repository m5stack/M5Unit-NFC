/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file file_system.hpp
  @brief File system base using isoDEP
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_ISODEP_FILE_SYSTEM_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_ISODEP_FILE_SYSTEM_HPP
#include "isoDEP.hpp"

namespace m5 {
namespace nfc {
namespace isodep {
class IsoDEP;
}

class FileSystem {
public:
    explicit FileSystem(m5::nfc::isodep::IsoDEP& isoDEP) : _isoDEP{isoDEP}
    {
    }
    virtual ~FileSystem() = default;

    ///@name ISO/IEC 7816-4 Standard commands
    ///@{
    bool selectFile(const uint8_t* aid, const uint8_t aid_len, const uint8_t param1 = 0x00,
                    const uint8_t param2 = 0x0C /* No response*/);
    bool selectFile(const uint16_t fid, const uint8_t param1 = 0x00, const uint8_t param2 = 0x0C /* No response */);

    inline bool selectMasterFile()
    {
        return selectFile(0x3F00, 0, 0);
    }

    bool verify(const uint8_t* password, const uint16_t pass_len, const uint8_t param2);
    inline bool verifyGlobal(const uint8_t* password, const uint16_t pass_len)
    {
        return verify(password, pass_len, 0x80);
    }
    inline bool verifySpecific(const uint8_t* password, const uint16_t pass_len)
    {
        return verify(password, pass_len, 0x00);
    }
    bool readBinary(std::vector<uint8_t>& out, const uint16_t offset, const uint16_t le /* 1..256 recommended */);
    ///@}

protected:
    m5::nfc::isodep::IsoDEP& _isoDEP;
};

}  // namespace nfc
}  // namespace m5
#endif
