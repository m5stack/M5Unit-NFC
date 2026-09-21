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
#include "nfc/a/mifare.hpp"
#include "nfc/ndef/ndef.hpp"
#include <m5_utility/stl/expected.hpp>
#include <m5_utility/conversion.hpp>
#include <array>
#include <algorithm>

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

namespace detail {
///@cond INTERNAL

inline uint16_t default_rx_capacity(const m5::nfc::isodep::IsoDEP& dep)
{
    const uint16_t cfg_rx = dep.config().max_frame_size_rx();
    const uint16_t base   = cfg_rx ? cfg_rx : 256;
    return std::max<uint16_t>(256, base);
}

inline void pack_le24(uint8_t out[3], const uint32_t value)
{
    out[0] = static_cast<uint8_t>(value & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
}

inline void pack_be24(uint8_t out[3], const uint32_t value)
{
    out[0] = static_cast<uint8_t>((value >> 16) & 0xFF);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>(value & 0xFF);
}

inline uint32_t unpack_le24(const uint8_t in[3])
{
    return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) | (static_cast<uint32_t>(in[2]) << 16);
}

///@endcond
}  // namespace detail

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
    uint8_t aid[3]{m5::nfc::a::mifare::desfire::DESFIRE_NDEF_AID[0], m5::nfc::a::mifare::desfire::DESFIRE_NDEF_AID[1],
                   m5::nfc::a::mifare::desfire::DESFIRE_NDEF_AID[2]};         //!< NDEF Tag Application AID
    uint8_t cc_file_no{m5::nfc::a::mifare::desfire::DESFIRE_CC_FILE_NO};      //!< CC file number (DESFire)
    uint8_t ndef_file_no{m5::nfc::a::mifare::desfire::DESFIRE_NDEF_FILE_NO};  //!< NDEF file number (DESFire)
    uint16_t cc_file_size{0x000F};                                            //!< CC file size (bytes)
    uint16_t ndef_file_size{2048};                                            //!< NDEF file size (bytes)
    uint8_t comm_mode{0x00};                                                  //!< Plain communication
    uint16_t access_rights{0xEEEE};                                           //!< DESFire access rights
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
  @details Something similar to APDU but different
  @param ins Native INS
  @param data Data
  @param data_len Data length
  @return Constructed command data
 */
std::vector<uint8_t> make_native_wrap_command(const uint8_t ins, const uint8_t* data = nullptr,
                                              const uint16_t data_len = 0);

/*!
  @brief DESFire status code (0x91xx)
  @param rx Receive data
  @param rx_len Receive data length
  @return DESFire status code, or 0xFF if the response is not a DESFire status response
 */
inline uint8_t status_code(const uint8_t* rx, const uint16_t rx_len)
{
    return (rx && rx_len >= 2 && rx[rx_len - 2] == 0x91) ? rx[rx_len - 1] : 0xFF;
}

/*!
  @brief Is the status of the received data successful?
  @param rx Receive data
  @param rx_len Receive data length
  @return True if the DESFire status code is success
 */
inline bool is_successful(const uint8_t* rx, const uint16_t rx_len)
{
    return status_code(rx, rx_len) == 0x00;
}

/*!
  @brief Is the received data still waiting for a response?
  @param rx Receive data
  @param rx_len Receive data length
  @return True if the DESFire status code indicates additional frame data
 */
inline bool is_more(const uint8_t* rx, const uint16_t rx_len)
{
    return status_code(rx, rx_len) == 0xAF;
}

/*!
  @brief Is duplicate error? (e.g. app/file already exists)
  @param rx Receive data
  @param rx_len Receive data length
  @return True if the DESFire status code indicates duplicate application or file
 */
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
    /*!
      @brief Constructor with NFCLayerA
      @param layer NFC-A layer
     */
    explicit DESFireFileSystem(m5::nfc::NFCLayerA& layer);
    /*!
      @brief Constructor with IsoDEP
      @param isoDEP ISO-DEP transport
     */
    explicit DESFireFileSystem(m5::nfc::isodep::IsoDEP& isoDEP) : FileSystem{isoDEP}
    {
    }

    /*!
      @brief Create a new application
      @param aid 3-byte application ID
      @param key_settings1 Key settings byte 1
      @param key_settings2 Key settings byte 2
      @param iso_fid Optional ISO file ID
      @param df_name Optional DF name
      @param df_name_len DF name length
      @return Success or DESFire status code on failure
     */
    m5::stl::expected<void, uint8_t> createApplication(const uint8_t aid[3], const uint8_t key_settings1,
                                                       const uint8_t key_settings2, const uint16_t iso_fid = 0,
                                                       const uint8_t* df_name = nullptr, const uint8_t df_name_len = 0);
    /*!
      @brief Select application by desfire_aid_t
      @param aid Application ID
      @return True if successful
     */
    inline bool selectApplication(const desfire_aid_t& aid)
    {
        return selectApplication(aid.data());
    }
    /*!
      @brief Select application by 3-byte AID
      @param aid 3-byte application ID
      @return True if successful
     */
    bool selectApplication(const uint8_t aid[3]);
    /*!
      @brief Select application by 24-bit AID value
      @param aid24 24-bit application ID value
      @return True if successful
     */
    bool selectApplication(const uint32_t aid24 = 0u);
    /*!
      @brief Delete application by 3-byte AID
      @param aid 3-byte application ID
      @return True if successful
     */
    bool deleteApplication(const uint8_t aid[3]);

    /*!
      @brief Get list of application IDs
      @param[out] out Application IDs
      @return True if successful
     */
    bool getApplicationIDs(std::vector<desfire_aid_t>& out);
    /*!
      @brief Get free memory of PICC
      @param[out] out Free memory in bytes
      @return True if successful
      @note Intended to be used before authentication (no secure messaging)
     */
    bool getFreeMemory(uint32_t& out);
    /*!
      @brief Get key settings of the currently selected application
      @param[out] key_settings Key settings byte
      @param[out] key_count Number of keys
      @return True if successful
     */
    bool getKeySettings(uint8_t& key_settings, uint8_t& key_count);
    /*!
      @brief Get list of file IDs in the currently selected application
      @param[out] out File IDs
      @return True if successful
     */
    bool getFileIDs(std::vector<uint8_t>& out);
    /*!
      @brief Get list of ISO file IDs in the currently selected application
      @param[out] out ISO file IDs
      @return True if successful
     */
    bool getISOFileIDs(std::vector<uint8_t>& out);
    /*!
      @brief Get file settings (plain)
      @param[out] out File settings
      @param file_no File number
      @return True if successful
     */
    bool getFileSettings(FileSettings& out, const uint8_t file_no);
    /*!
      @brief Get file settings (EV2 MAC)
      @param[out] out File settings
      @param file_no File number
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool getFileSettingsEV2(FileSettings& out, const uint8_t file_no, Ev2Context& ctx);
    /*!
      @brief Get file settings (EV2 Full)
      @param[out] out File settings
      @param file_no File number
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool getFileSettingsEV2Full(FileSettings& out, const uint8_t file_no, Ev2Context& ctx);

    /*!
      @brief Change file settings (plain)
      @param file_no File number
      @param file_option File communication option
      @param access_rights Access rights
      @return True if successful
     */
    bool changeFileSettings(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights);
    /*!
      @brief Change file settings (EV2 MAC)
      @param file_no File number
      @param file_option File communication option
      @param access_rights Access rights
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool changeFileSettingsEV2(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights,
                               Ev2Context& ctx);
    /*!
      @brief Change file settings (EV2 Full)
      @param file_no File number
      @param file_option File communication option
      @param access_rights Access rights
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool changeFileSettingsEV2Full(const uint8_t file_no, const uint8_t file_option, const uint16_t access_rights,
                                   Ev2Context& ctx);

    /*!
      @brief Format the PICC (erases all applications and files)
      @param picc_master_key PICC master key, or nullptr to skip authentication
      @param mode Authentication mode
      @return True if successful
     */
    bool formatPICC(const uint8_t* picc_master_key, const AuthMode mode = AuthMode::Auto);

    /*!
      @brief Create a Standard Data File
      @param file_no File number
      @param iso_fid ISO file ID
      @param comm_mode Communication mode
      @param access_rights Access rights
      @param file_size File size in bytes
      @return True if successful
     */
    bool createStdDataFile(const uint8_t file_no, const uint16_t iso_fid, const uint8_t comm_mode,
                           const uint16_t access_rights, const uint32_t file_size);

    /*!
      @brief Set file renaming configuration (DESFire Light; requires AppMasterKey + CommMode.Full)
      @param first First file rename entry
      @param second Optional second file rename entry
      @return True if successful
     */
    bool setConfigurationFileRenaming(const FileRename& first, const FileRename* second = nullptr);
    /*!
      @brief Set file renaming configuration (EV2 Full)
      @param first First file rename entry
      @param second Optional second file rename entry
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool setConfigurationFileRenamingEV2Full(const FileRename& first, const FileRename* second, Ev2Context& ctx);

    /*!
      @brief Delete TransactionMAC file (required for ISOReadBinary to work)
      @param file_no File number of TMAC file (default 0)
      @param ctx EV2 context (must be authenticated with AppMasterKey)
      @return True if successful
      @note DESFire Light blocks ISOReadBinary when TMAC file exists
     */
    bool deleteTransactionMACFileEV2Full(const uint8_t file_no, Ev2Context& ctx);

    /*!
      @brief Create TransactionMAC file
      @param file_no File number for TMAC file
      @param comm_mode Communication mode (0=Plain, 1=MAC, 3=Full)
      @param access_rights Access rights
      @param tmac_key 16-byte TMAC key
      @param tmac_key_ver Key version
      @param ctx EV2 context (must be authenticated with AppMasterKey)
      @return True if successful
     */
    bool createTransactionMACFileEV2Full(const uint8_t file_no, const uint8_t comm_mode, const uint16_t access_rights,
                                         const uint8_t tmac_key[16], const uint8_t tmac_key_ver, Ev2Context& ctx);
    /*!
      @brief Change application name/ISO file ID (EV2 Full)
      @param df_name New DF name
      @param df_name_len DF name length
      @param iso_fid New ISO file ID
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool setConfigurationAppNameEV2Full(const uint8_t* df_name, uint8_t df_name_len, uint16_t iso_fid, Ev2Context& ctx);

    /*!
      @brief Read data from DESFire file
      @param[out] out Output buffer
      @param file_no File number
      @param offset Offset in file
      @param length Length to read
      @return True if successful
     */
    bool readData(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset, const uint32_t length);
    /*!
      @brief Read data from DESFire Light file
      @param[out] out Output buffer
      @param file_no File number
      @param offset Offset in file
      @param length Length to read
      @return True if successful
     */
    bool readDataLight(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset, const uint32_t length);
    /*!
      @brief Read data from DESFire Light file (EV2 Full)
      @param[out] out Output buffer
      @param file_no File number
      @param offset Offset in file
      @param length Length to read
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool readDataLightEV2Full(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                              const uint32_t length, Ev2Context& ctx);
    /*!
      @brief Read data from DESFire Light file (EV2 MAC)
      @param[out] out Output buffer
      @param file_no File number
      @param offset Offset in file
      @param length Length to read
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool readDataLightEV2(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                          const uint32_t length, Ev2Context& ctx);
    /*!
      @brief Write data to DESFire file
      @param file_no File number
      @param offset Offset in file
      @param data Data to write
      @param data_len Data length
      @return True if successful
     */
    bool writeData(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len);
    /*!
      @brief Write data to DESFire Light file
      @param file_no File number
      @param offset Offset in file
      @param data Data to write
      @param data_len Data length
      @return True if successful
     */
    bool writeDataLight(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len);
    /*!
      @brief Write data to DESFire Light file (EV2 MAC)
      @param file_no File number
      @param offset Offset in file
      @param data Data to write
      @param data_len Data length
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool writeDataLightEV2(const uint8_t file_no, const uint32_t offset, const uint8_t* data, const uint32_t data_len,
                           Ev2Context& ctx);
    /*!
      @brief Write data to DESFire Light file (EV2 Full)
      @param file_no File number
      @param offset Offset in file
      @param data Data to write
      @param data_len Data length
      @param[in,out] ctx EV2 secure messaging context
      @return True if successful
     */
    bool writeDataLightEV2Full(const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                               const uint32_t data_len, Ev2Context& ctx);

    /*!
      @brief Authenticate with DES key (legacy)
      @param key_no Key number
      @param key 16-byte DES/3DES key buffer
      @return True if successful
     */
    bool authenticateDES(const uint8_t key_no, const uint8_t key[16]);
    /*!
      @brief Authenticate with ISO key
      @param key_no Key number
      @param key 16-byte ISO key buffer
      @return True if successful
     */
    bool authenticateISO(const uint8_t key_no, const uint8_t key[16]);
    /*!
      @brief Authenticate with AES key
      @param key_no Key number
      @param key 16-byte AES key
      @return True if successful
     */
    bool authenticateAES(const uint8_t key_no, const uint8_t key[16]);
    /*!
      @brief Authenticate (AuthenticateEV2First, AES) and prepare EV2 context
      @param key_no Key number
      @param key 16-byte AES key
      @param[out] ctx EV2 secure messaging context
      @return True if successful
     */
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
