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
#include "nfc/ndef/ndef.hpp"
#include <m5_utility/stl/expected.hpp>
#include <array>

namespace m5 {
namespace nfc {
class NFCLayerA;
namespace a {
namespace mifare {
/*!
  @namespace desfire
  @brief For MIFARE DESFire
 */
namespace desfire {

constexpr uint8_t DESFIRE_APDU_CLA{0x90};
constexpr uint8_t DESFIRE_LIGHT_INS_READ_DATA{0xAD};
constexpr uint8_t DESFIRE_LIGHT_INS_WRITE_DATA{0x8D};

///@name File number
///@{
using file_no_t = uint8_t;                //!< Alias for file number
constexpr file_no_t MINIMUM_FILE_NO{0};   //!< Minimum file number
constexpr file_no_t MAXIMUM_FILE_NO{31};  //!< Maximum file number
///@}

constexpr uint8_t MAXIMUM_FILES{MAXIMUM_FILE_NO - MINIMUM_FILE_NO + 1};  //!< Files max

/*!
  @struct FileSettings
  @brief DESFire file settings (minimal fields for StdDataFile)
 */
struct FileSettings {
    uint8_t file_type{};
    uint8_t comm_mode{};
    uint16_t access_rights{};
    uint32_t file_size{};
};

/*!
  @struct desfire_aid_t
  @brief 24bit Application ID
 */
struct desfire_aid_t {
    uint8_t aid[3]{};  // BE
    uint8_t _pad{};
    inline constexpr uint32_t aid24() const noexcept
    {
        // Big-endian
        return ((uint32_t)aid[0] << 16) | ((uint32_t)aid[1] << 8) | aid[2];
    }
    inline constexpr const uint8_t* data() const noexcept
    {
        return aid;
    }
    inline explicit operator uint32_t() const noexcept
    {
        return aid24();
    }
};
inline bool operator==(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return a.aid[0] == b.aid[0] && a.aid[1] == b.aid[1] && a.aid[2] == b.aid[2];
}
inline bool operator!=(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return !(a == b);
}
inline bool operator<(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return a.aid24() < b.aid24();
}

/*!
  @enum AuthMode
  @brief Authentication mode
 */
enum class AuthMode : uint8_t {
    Auto,  //!< Try DES then AES
    DES,   //!< DES/3DES only
    AES,   //!< AES only
};

/*!
  @struct NdefFormatOptions
  @brief Options for formatting DESFire as Type4 NDEF
 */
struct NdefFormatOptions {
    m5::nfc::ndef::type4::CapabilityContainer cc;  //!< CC contents
    uint8_t aid[3]{m5::nfc::ndef::type4::DESFIRE_NDEF_AID[0], m5::nfc::ndef::type4::DESFIRE_NDEF_AID[1],
                   m5::nfc::ndef::type4::DESFIRE_NDEF_AID[2]};         //!< NDEF Tag Application AID
    uint8_t cc_file_no{m5::nfc::ndef::type4::DESFIRE_CC_FILE_NO};      //!< CC file number (DESFire)
    uint8_t ndef_file_no{m5::nfc::ndef::type4::DESFIRE_NDEF_FILE_NO};  //!< NDEF file number (DESFire)
    uint16_t cc_file_size{0x000F};                                     //!< CC file size (bytes)
    uint16_t ndef_file_size{2048};                                     //!< NDEF file size (bytes)
    uint8_t comm_mode{0x00};                                           //!< Plain communication
    uint16_t access_rights{0xEEEE};                                    //!< DESFire access rights
    uint8_t key_settings1{0x09};              //!< AN11004: Create/Delete requires auth, Get* requires auth
    uint8_t key_settings2{0x21};              //!< ISO FID support(bit5) + NumKeys=1 + DES/3DES
    const uint8_t* picc_master_key{nullptr};  //!< DES/3DES master key (PICC), or nullptr to skip auth
    const uint8_t* app_master_key{nullptr};   //!< DES/3DES master key (App), or nullptr to skip auth
    AuthMode auth_mode{AuthMode::Auto};       //!< Authentication mode
};

/*!
  @struct FileRename
  @brief File renaming parameters for DESFire Light SetConfiguration
 */
struct FileRename {
    uint8_t old_file_no{};   //!< Current file number
    uint8_t new_file_no{};   //!< New file number
    uint16_t new_file_id{};  //!< New ISO File ID (LSB first in command)
};

/*!
  @struct Ev2Context
  @brief Session context for EV2 secure messaging
 */
struct Ev2Context {
    uint8_t ti[4]{};            //!< Transaction Identifier
    uint16_t cmd_ctr{};         //!< Command Counter
    uint8_t ses_enc_key[16]{};  //!< Session ENC key
    uint8_t ses_mac_key[16]{};  //!< Session MAC key
};
/*!
  @brief Make native wrap command
  @details Something similar to ADPU but different
  @param ins Native INS
  @param data Data
  @param data_len Data length
  @return Constructed command data
 */
std::vector<uint8_t> make_native_wrap_command(const uint8_t ins, const uint8_t* data = nullptr,
                                              const uint16_t data_len = 0);

//! @brief DESFire status code (0x91xx)
inline uint8_t status_code(const uint8_t* rx, const uint16_t rx_len)
{
    return (rx && rx_len >= 2 && rx[rx_len - 2] == 0x91) ? rx[rx_len - 1] : 0xFF;
}

//! @brief Is the status of the received data successful?
inline bool is_successful(const uint8_t* rx, const uint16_t rx_len)
{
    return status_code(rx, rx_len) == 0x00;
}

//! @brief Is the received data still waiting for a response?
inline bool is_more(const uint8_t* rx, const uint16_t rx_len)
{
    return status_code(rx, rx_len) == 0xAF;
}

//! @brief Is duplicate error? (e.g. app/file already exists)
inline bool is_duplicate(const uint8_t* rx, const uint16_t rx_len)
{
    return status_code(rx, rx_len) == 0xDE;
}

/*!
  @class DESFireFileSystem
  @brief File system for MIFARE DESFire
 */
class DESFireFileSystem : public FileSystem {
public:
    explicit DESFireFileSystem(m5::nfc::NFCLayerA& layer);
    explicit DESFireFileSystem(m5::nfc::isodep::IsoDEP& isoDEP) : FileSystem{isoDEP}
    {
    }

    m5::stl::expected<void, uint8_t> createApplication(const uint8_t aid[3], const uint8_t key_settings1,
                                                       const uint8_t key_settings2, const uint16_t iso_fid = 0,
                                                       const uint8_t* df_name = nullptr, const uint8_t df_name_len = 0);
    inline bool selectApplication(const desfire_aid_t& aid)
    {
        return selectApplication(aid.data());
    }
    bool selectApplication(const uint8_t aid[3]);
    bool selectApplication(const uint32_t aid24 = 0u);
    bool deleteApplication(const uint8_t aid[3]);

    bool getApplicationIDs(std::vector<desfire_aid_t>& out);
    // NOTE: getFreeMemory is intended to be used before authentication (no secure messaging).
    bool getFreeMemory(uint32_t& out);
    bool getKeySettings(uint8_t& key_settings, uint8_t& key_count);
    bool getFileIDs(std::vector<uint8_t>& out);
    bool getFileSettings(FileSettings& out, const uint8_t file_no);
    bool getFileSettingsEV2(FileSettings& out, const uint8_t file_no, Ev2Context& ctx);

    bool changeFileSettingsEV2Full(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights,
                                   Ev2Context& ctx);
    bool changeFileSettingsEV2(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights,
                               Ev2Context& ctx);
    bool changeFileSettings(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights);

    bool formatPICC(const uint8_t* picc_master_key, const AuthMode mode = AuthMode::Auto);

    bool createStdDataFile(const uint8_t file_no, const uint16_t iso_fid, const uint8_t comm_mode,
                           const uint16_t access_rights, const uint32_t file_size);

    // DESFire Light: requires AppMasterKey authentication and CommMode.Full.
    bool setConfigurationFileRenaming(const FileRename& first, const FileRename* second = nullptr);
    bool setConfigurationFileRenamingEV2Full(const FileRename& first, const FileRename* second, Ev2Context& ctx);

    bool createNDEFFiles(const uint32_t max_ndef_size);

    /*!
      @brief Read data from DESFire file
      @param[out] out Output buffer
      @param file_no File number
      @param offset Offset in file
      @param length Length to read
      @return True if successful
     */
    bool readData(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset, const uint32_t length);
    bool readDataLight(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset, const uint32_t length);
    bool readDataLightEV2Full(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                              const uint32_t length, Ev2Context& ctx);
    bool readDataLightEV2(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                          const uint32_t length, Ev2Context& ctx);
    bool writeData(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len);
    bool writeDataLight(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len);
    bool writeDataEV2Mac(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len,
                         Ev2Context& ctx);
    bool writeDataEV2Full(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len,
                          Ev2Context& ctx);

    bool authenticateDES(const uint8_t key_no, const uint8_t key[16]);
    bool authenticateISO(const uint8_t key_no, const uint8_t key[16]);
    bool authenticateAES(const uint8_t key_no, const uint8_t key[16]);
    bool authenticateEV2First(const uint8_t key_no, const uint8_t key[16], Ev2Context& ctx);

protected:
    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len);
};

}  // namespace desfire
}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
#endif
