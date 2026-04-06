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
  @struct FCP
  @brief File Control Parameters
  @todo Add more item
*/
struct FCP {
    uint16_t fid{};                 //!< @brief File ID (FID)
    uint16_t file_size{};           //!< @brief File size in bytes
    uint8_t file_descriptor{0x01};  //!< @brief File descriptor (default: transparent EF)
    uint8_t file_size_tag{0x80};    //!< @brief File size TLV tag (default: 0x80)

    /*!
      @brief Build FCP TLV (tag 0x62)
      @return Encoded FCP
     */
    std::vector<uint8_t> to_tlv() const
    {
        std::vector<uint8_t> fcp;
        fcp.reserve(16);

        // File Descriptor (0x82)
        fcp.push_back(0x82);
        fcp.push_back(1);
        fcp.push_back(file_descriptor);

        // File ID (0x83)
        fcp.push_back(0x83);
        fcp.push_back(2);
        fcp.push_back(static_cast<uint8_t>((fid >> 8) & 0xFF));
        fcp.push_back(static_cast<uint8_t>(fid & 0xFF));

        // File Size (tag: file_size_tag)
        fcp.push_back(file_size_tag);
        fcp.push_back(2);
        fcp.push_back(static_cast<uint8_t>((file_size >> 8) & 0xFF));
        fcp.push_back(static_cast<uint8_t>(file_size & 0xFF));

        //
        std::vector<uint8_t> out;
        out.reserve(fcp.size() + 2);
        out.push_back(0x62);
        out.push_back(static_cast<uint8_t>(fcp.size()));
        out.insert(out.end(), fcp.begin(), fcp.end());
        return out;
    }
};

/*!
  @brief Parse FCI (tag 0x6F) and fill FCP
  @param data FCI data
  @param len FCI length
  @param[out] fcp Output FCP
  @return True if FCI parsed, false otherwise
 */
bool parseFCI(FCP& fcp, const uint8_t* data, const uint32_t len);

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

    /*!
      @brief CREATE FILE
      @param fcp File control parameters
      @param fcp_len fcp length
      @return True if successful
     */
    bool createFile(const uint8_t* fcp, const uint16_t fcp_len);
    /*!
      @brief CREATE FILE
      @param fcp File control parameters
      @return True if successful
     */
    bool createFile(const FCP& fcp);
    /*!
      @brief CREATE FILE
      @param fid FileID
      @param file_size File size
      @return True if successful
     */
    bool createFile(const uint16_t fid, const uint16_t file_size);

    /*!
      @brief SELECT FILE (generic)
      @param by Selection method
      @param occ Selection occurrence
      @param res Response format
      @param param Identifier data
      @param param_len Identifier length
      @return True if successful
     */
    bool selectFile(const m5::nfc::apdu::SelectBy by, const m5::nfc::apdu::SelectOccurrence occ,
                    const m5::nfc::apdu::SelectResponse res, const uint8_t* param, const uint8_t param_len);

    /*!
      @brief SELECT by File ID with explicit response type
      @param fid File ID
      @param res Response format
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectByFileId(const uint16_t fid,
                        const m5::nfc::apdu::SelectResponse res   = m5::nfc::apdu::SelectResponse::FCI,
                        const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT by File ID with auto response fallback (None->FCI->FCP)
      @param fid File ID
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectFileIdAuto(const uint16_t fid,
                          const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT by DF Name with explicit response type
      @param aid DF name (AID)
      @param aid_len AID length
      @param res Response format
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectByDfName(const uint8_t* aid, const uint8_t aid_len,
                        const m5::nfc::apdu::SelectResponse res   = m5::nfc::apdu::SelectResponse::FCI,
                        const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT by DF Name with auto response fallback (FCI->None->FCP)
      @param aid DF name (AID)
      @param aid_len AID length
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectDfNameAuto(const uint8_t* aid, const uint8_t aid_len,
                          const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT by path (MF or current DF)
      @param path Path data
      @param path_len Path length
      @param from_mf Use MF as origin if true
      @param res Response format
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectByPath(const uint8_t* path, const uint8_t path_len, const bool from_mf = true,
                      const m5::nfc::apdu::SelectResponse res   = m5::nfc::apdu::SelectResponse::FCI,
                      const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT parent DF
      @param res Response format
      @param occ Selection occurrence
      @return True if successful
     */
    bool selectParent(const m5::nfc::apdu::SelectResponse res   = m5::nfc::apdu::SelectResponse::FCI,
                      const m5::nfc::apdu::SelectOccurrence occ = m5::nfc::apdu::SelectOccurrence::FirstOrOnly);
    /*!
      @brief SELECT MF (Master File)
      @return True if successful
     */
    inline bool selectMasterFile()
    {
        return selectByFileId(m5::nfc::apdu::master_file_id);
    }

    /*!
      @brief VERIFY (generic)
      @param password Password data
      @param pass_len Password length
      @param param2 P2 (reference data type)
      @return True if successful
     */
    bool verify(const uint8_t* password, const uint16_t pass_len, const uint8_t param2);
    /*!
      @brief VERIFY global reference data
      @param password Password data
      @param pass_len Password length
      @return True if successful
     */
    inline bool verifyGlobal(const uint8_t* password, const uint16_t pass_len)
    {
        return verify(password, pass_len, 0x80);
    }
    /*!
      @brief VERIFY specific reference data
      @param password Password data
      @param pass_len Password length
      @return True if successful
     */
    inline bool verifySpecific(const uint8_t* password, const uint16_t pass_len)
    {
        return verify(password, pass_len, 0x00);
    }
    /*!
      @brief READ BINARY
      @param[out] out Output buffer
      @param offset File offset
      @param le Expected length (1..256 recommended)
      @return True if successful
     */
    bool readBinary(std::vector<uint8_t>& out, const uint16_t offset, const uint16_t le /* 1..256 recommended */);
    /*!
      @brief UPDATE BINARY
      @param offset File offset
      @param data Data to write
      @param data_len Length to write
      @return True if successful
     */
    bool updateBinary(const uint16_t offset, const uint8_t* data, const uint16_t data_len);
    ///@}

    /*!
      @brief Last SELECT response data (SW excluded)
      @return Response data
     */
    inline const std::vector<uint8_t>& lastSelectData() const
    {
        return _last_select_fci;
    }

protected:
    m5::nfc::isodep::IsoDEP& _isoDEP;
    std::vector<uint8_t> _last_select_fci{};
};

}  // namespace nfc
}  // namespace m5
#endif
