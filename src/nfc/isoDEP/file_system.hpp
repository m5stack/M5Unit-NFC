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
#include "nfc/apdu/apdu.hpp"

namespace m5 {
namespace nfc {
namespace isodep {
class IsoDEP;
}

/*!
  @class FileSystem
  @brief  ISO/IEC 7816-4 file system
 */
class FileSystem {
public:
    explicit FileSystem(m5::nfc::isodep::IsoDEP& isoDEP) : _isoDEP{isoDEP}
    {
    }
    virtual ~FileSystem() = default;

    ///@name ISO/IEC 7816-4 Standard commands
    ///@{

    bool selectFile(const m5::nfc::apdu::SelectBy by, const m5::nfc::apdu::SelectOccurrence occ,
                    const m5::nfc::apdu::SelectResponse res, const uint8_t* param, const uint8_t param_len);
    bool selectByFileId(const uint16_t fid,
                        const m5::nfc::apdu::SelectResponse res = m5::nfc::apdu::SelectResponse::FCI,
                        const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    bool selectByDfName(const uint8_t* aid, const uint8_t aid_len,
                        const m5::nfc::apdu::SelectResponse res = m5::nfc::apdu::SelectResponse::FCI,
                        const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    bool selectByPath(const uint8_t* path, const uint8_t path_len, const bool from_mf = true,
                      const m5::nfc::apdu::SelectResponse res = m5::nfc::apdu::SelectResponse::FCI,
                      const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    bool selectParent(const m5::nfc::apdu::SelectResponse res = m5::nfc::apdu::SelectResponse::FCI,
                      const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    inline bool selectMasterFile()
    {
        return selectByFileId(m5::nfc::apdu::master_file_id);
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
