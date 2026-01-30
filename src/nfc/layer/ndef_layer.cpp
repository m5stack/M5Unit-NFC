/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_layer.cpp
  @brief Common layer for NDEF related
*/
#include "ndef_layer.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/ndef/ndef_tlv.hpp"
#include "nfc/a/mifare.hpp"
#include "nfc/isoDEP/file_system.hpp"
#include "nfc/isoDEP/desfire_file_system.hpp"
#include "nfc/ndef/ndef_record.hpp"
#include <M5Utility.hpp>
#include <functional>
#include <algorithm>
#include <limits>
#include <numeric>

using namespace m5::nfc;
using namespace m5::nfc::ndef;
namespace desfire = m5::nfc::a::mifare::desfire;

namespace {
type4::FileControlTagBits tag_bits_to_file_control_tag_bits(const TagBits tb)
{
    type4::FileControlTagBits bits{};
    if (tb & make_tag_bits(Tag::Message)) {
        bits |= type4::fcBitsMessage;
    }
    if (tb & make_tag_bits(Tag::Proprietary)) {
        bits |= type4::make_fc_bits(type4::FileControlTag::Proprietary);
    }
    return bits;
}

bool read_cc_common(const std::function<bool(std::vector<uint8_t>& out, uint16_t offset, uint16_t len)>& read_cc,
                    m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    std::vector<uint8_t> head;
    if (!read_cc(head, 0, 2) || head.size() < 2) {
        return false;
    }
    const uint16_t cc_len = (static_cast<uint16_t>(head[0]) << 8) | head[1];
    if (cc_len < 7) {
        return false;
    }

    std::vector<uint8_t> raw;
    raw.reserve(cc_len);
    uint16_t offset = 0;
    while (offset < cc_len) {
        const uint16_t chunk = std::min<uint16_t>(static_cast<uint16_t>(cc_len - offset), 0xFF);
        std::vector<uint8_t> part;
        if (!read_cc(part, offset, chunk) || part.size() < chunk) {
            return false;
        }
        raw.insert(raw.end(), part.begin(), part.begin() + chunk);
        offset = static_cast<uint16_t>(offset + chunk);
    }
    if (raw.size() < cc_len) {
        return false;
    }
    return cc.parse(raw.data(), raw.size());
}

bool build_type4_cc(std::vector<uint8_t>& out, const uint16_t ndef_fid, const uint16_t ndef_size,
                    const uint8_t read_access, const uint8_t write_access)
{
    constexpr uint16_t cc_len         = 0x000F;
    constexpr uint8_t mapping_version = 0x20;
    //    constexpr uint16_t mle           = 0x003A;
    //    constexpr uint16_t mlc           = 0x0034;

    constexpr uint16_t mle = 120;
    constexpr uint16_t mlc = 120;

    out.clear();
    if (!ndef_fid || !ndef_size) {
        return false;
    }
    out.reserve(cc_len);
    out.push_back(static_cast<uint8_t>((cc_len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(cc_len & 0xFF));
    out.push_back(mapping_version);
    out.push_back(static_cast<uint8_t>((mle >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(mle & 0xFF));
    out.push_back(static_cast<uint8_t>((mlc >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(mlc & 0xFF));
    out.push_back(0x04);
    out.push_back(0x06);
    out.push_back(static_cast<uint8_t>((ndef_fid >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ndef_fid & 0xFF));
    out.push_back(static_cast<uint8_t>((ndef_size >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ndef_size & 0xFF));
    out.push_back(read_access);
    out.push_back(write_access);
    return out.size() >= 7;
}

bool build_desfire_cc(std::vector<uint8_t>& out, uint16_t& ndef_fid, uint16_t& ndef_size,
                      const a::mifare::desfire::NdefFormatOptions& opt)
{
    out.clear();
    if (opt.cc.fctlvs.empty()) {
        return false;
    }
    const auto& fct = opt.cc.fctlvs.front();
    if (!fct.ndef_file_id) {
        return false;
    }
    const uint16_t cc_len = opt.cc_file_size ? opt.cc_file_size : 0x000F;
    const uint8_t mapping = opt.cc.mapping_version ? opt.cc.mapping_version : 0x20;
    const uint16_t mle    = opt.cc.mle ? opt.cc.mle : 0x003A;
    const uint16_t mlc    = opt.cc.mlc ? opt.cc.mlc : 0x0034;

    ndef_fid  = fct.ndef_file_id;
    ndef_size = fct.ndef_file_size ? fct.ndef_file_size : opt.ndef_file_size;
    if (fct.ndef_file_size && opt.ndef_file_size && fct.ndef_file_size != opt.ndef_file_size) {
        return false;
    }
    if (!ndef_size) {
        return false;
    }

    out.reserve(cc_len);
    out.push_back(static_cast<uint8_t>((cc_len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(cc_len & 0xFF));
    out.push_back(mapping);
    out.push_back(static_cast<uint8_t>((mle >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(mle & 0xFF));
    out.push_back(static_cast<uint8_t>((mlc >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(mlc & 0xFF));
    out.push_back(0x04);
    out.push_back(0x06);
    out.push_back(static_cast<uint8_t>((ndef_fid >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ndef_fid & 0xFF));
    out.push_back(static_cast<uint8_t>((ndef_size >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ndef_size & 0xFF));
    out.push_back(fct.read_access);
    out.push_back(fct.write_access);
    return out.size() >= 7;
}

using desfire::access_denied;
using desfire::access_free;
using desfire::required_write_key_no_from_access_rights;

}  // namespace

namespace m5 {
namespace nfc {
namespace ndef {

// Check CC/AB
bool NDEFLayer::isValidFormat(bool& valid, const m5::nfc::NFCForumTag ftag)
{
    valid = false;

    switch (ftag) {
        case NFCForumTag::Type2: {
            type2::CapabilityContainer cc{};
            if (readCapabilityContainer(cc)) {
                valid = cc.valid();
                return true;
            }
        } break;

        case NFCForumTag::Type3: {
            type3::AttributeBlock ab{};
            if (readAttributeBlock(ab)) {
                valid = ab.valid();
                return true;
            }
        } break;
        case NFCForumTag::Type4: {
            type4::CapabilityContainer cc{};
            if (readCapabilityContainer(cc)) {
                valid = cc.valid();
                return true;
            }
            // In the case of DESFire, failures are considered to be non-NEDF format
            if (is_file_system_desfire(_interface.supportsFilesystem())) {
                valid = false;
                return true;
            }
        }; break;
        case NFCForumTag::Type5: {
            type5::CapabilityContainer cc{};
            if (readCapabilityContainer(cc)) {
                valid = cc.valid();
                return true;
            }
        } break;
        case NFCForumTag::Type1:
        default:
            break;
    }
    return false;
}

bool NDEFLayer::prepare_desfire_light()
{
    using desfire::DESFIRE_DEFAULT_KEY;
    using desfire::DESFIRE_LIGHT_CC_FILE_NO;
    using desfire::DESFIRE_LIGHT_DF_NAME;
    using desfire::DESFIRE_LIGHT_NDEF_FILE_NO;
    using desfire::DESFIRE_LIGHT_NDEF_FILE_SIZE;
    using type4::NDEF_AID;
    using type4::NDEF_APP_FID;
    using type4::NDEF_FILE_ID;

    if (!is_file_system_desfire_light(_interface.supportsFilesystem())) {
        return false;
    }
    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    // Select DF
    a::mifare::desfire::DESFireFileSystem dfs(*dep);
    const bool ndef_aid_available = dfs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID));
    if (!ndef_aid_available) {
        // If NDEF is not selectable, select Light default
        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
            M5_LIB_LOGE("select default DF failed");
            return false;
        }
    }

    // Rename file ID to NDEF format
    if (!dfs.selectFileIdAuto(type4::CC_FILE_ID)) {
        M5_LIB_LOGE(">>>> select CC(E103) failed -> rename");
        a::mifare::desfire::FileRename cc_rename{};
        cc_rename.old_file_no = DESFIRE_LIGHT_CC_FILE_NO;
        cc_rename.new_file_no = DESFIRE_LIGHT_CC_FILE_NO;
        cc_rename.new_file_id = type4::CC_FILE_ID;
        a::mifare::desfire::FileRename ndef_rename{};
        ndef_rename.old_file_no = DESFIRE_LIGHT_NDEF_FILE_NO;
        ndef_rename.new_file_no = DESFIRE_LIGHT_NDEF_FILE_NO;
        ndef_rename.new_file_id = NDEF_FILE_ID;

        a::mifare::desfire::Ev2Context ctx{};
        if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx)) {
            M5_LIB_LOGE("auth EV2 failed");
            return false;
        }
        if (!dfs.setConfigurationFileRenamingEV2Full(cc_rename, &ndef_rename, ctx)) {
            M5_LIB_LOGE("setConfiguration rename failed");
            return false;
        }
    }

    a::mifare::desfire::Ev2Context ctx{};
    if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx)) {
        M5_LIB_LOGE("prepare_desfire_light: auth EV2 failed (write)");
        return false;
    }

    // Get CC/NEDF file settings
    a::mifare::desfire::FileSettings cc_settings{};
    if (!dfs.getFileSettingsEV2(cc_settings, DESFIRE_LIGHT_CC_FILE_NO, ctx)) {
        M5_LIB_LOGE("prepare_desfire_light: getFileSettings CC failed");
        return false;
    }
    a::mifare::desfire::FileSettings ndef_settings{};
    if (!dfs.getFileSettingsEV2(ndef_settings, DESFIRE_LIGHT_NDEF_FILE_NO, ctx)) {
        M5_LIB_LOGE("prepare_desfire_light: getFileSettings NDEF failed");
        return false;
    }
    M5_LIB_LOGE("prepare_desfire_light: CC comm:%u NDEF comm:%u", cc_settings.comm_mode, ndef_settings.comm_mode);
    M5_LIB_LOGE("prepare_desfire_light: CC type:%u ar:%04X size:%u", cc_settings.file_type, cc_settings.access_rights,
                cc_settings.file_size);
    M5_LIB_LOGE("prepare_desfire_light: NDEF type:%u ar:%04X size:%u", ndef_settings.file_type,
                ndef_settings.access_rights, ndef_settings.file_size);

    // Change file settings for NDEF (No auth, plain)
    auto change_file_settings_mode = [&dfs, &ctx](const uint8_t file_no, const uint8_t file_opt,
                                                  const uint16_t access_rights, const uint8_t comm_ar) {
        switch (comm_ar & 0x0F /* Access righst For change */) {
            case 0x0E:
                return dfs.changeFileSettings(file_no, file_opt, access_rights);
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
                return dfs.changeFileSettingsEV2Full(file_no, file_opt, access_rights, ctx);
            default:
                return false;
        }
    };

    constexpr uint16_t free_access_rights{0xEEEE};  // All free access (No auth)
    constexpr uint8_t plain_comm_mode{0x00};        // Plain
    constexpr uint8_t file_option = (plain_comm_mode & 0x03);
    if (cc_settings.access_rights != free_access_rights || cc_settings.comm_mode != plain_comm_mode) {
        if (!change_file_settings_mode(DESFIRE_LIGHT_CC_FILE_NO, file_option, free_access_rights,
                                       cc_settings.access_rights)) {
            M5_LIB_LOGE("changeFileSettings CC failed");
            return false;
        }
        cc_settings.access_rights = free_access_rights;
        cc_settings.comm_mode     = plain_comm_mode;
    }
    if (ndef_settings.access_rights != free_access_rights || ndef_settings.comm_mode != plain_comm_mode) {
        if (!change_file_settings_mode(DESFIRE_LIGHT_NDEF_FILE_NO, file_option, free_access_rights,
                                       ndef_settings.access_rights)) {
            M5_LIB_LOGE("changeFileSettings NDEF failed");
            return false;
        }
        ndef_settings.access_rights = free_access_rights;
        ndef_settings.comm_mode     = plain_comm_mode;
    }

    // Write CC/empty NDEF
    auto write_with_mode = [&dfs, &ctx](const uint8_t file_no, const uint8_t* data, const uint32_t data_len,
                                        const uint8_t comm_mode) {
        switch (comm_mode) {
            case 0x00:
                return dfs.writeDataLight(file_no, 0, data, data_len);
            case 0x01:
                return dfs.writeDataLightEV2(file_no, 0, data, data_len, ctx);
            case 0x03:
                return dfs.writeDataLightEV2Full(file_no, 0, data, data_len, ctx);
            default:
                return false;
        }
    };

    std::vector<uint8_t> cc;
    if (!build_type4_cc(cc, NDEF_FILE_ID, DESFIRE_LIGHT_NDEF_FILE_SIZE, 0x00, 0x00)) {
        return false;
    }
    const int cc_key = required_write_key_no_from_access_rights(cc_settings.access_rights);
    if (cc_key == access_denied ||
        (cc_key >= 0 && !dfs.authenticateEV2First(static_cast<uint8_t>(cc_key), DESFIRE_DEFAULT_KEY, ctx))) {
        M5_LIB_LOGE("auth EV2 failed (CC key %d)", cc_key);
        return false;
    }
    if (!write_with_mode(DESFIRE_LIGHT_CC_FILE_NO, cc.data(), static_cast<uint32_t>(cc.size()),
                         cc_settings.comm_mode)) {
        M5_LIB_LOGE("write CC failed (comm %u)", cc_settings.comm_mode);
        return false;
    }

    const uint8_t nlen0[2] = {0x00, 0x00};
    const int ndef_key     = required_write_key_no_from_access_rights(ndef_settings.access_rights);
    if (ndef_key == access_denied ||
        (ndef_key >= 0 && !dfs.authenticateEV2First(static_cast<uint8_t>(ndef_key), DESFIRE_DEFAULT_KEY, ctx))) {
        M5_LIB_LOGE("auth EV2 failed (NDEF key %d)", ndef_key);
        return false;
    }
    if (!write_with_mode(DESFIRE_LIGHT_NDEF_FILE_NO, nlen0, sizeof(nlen0), ndef_settings.comm_mode)) {
        M5_LIB_LOGE("write NLEN failed (comm %u)", ndef_settings.comm_mode);
        return false;
    }

    // Write FCI file (1Fh) for ISO SELECT response
    // This is required for iPhone/NFC readers to recognize the tag as T4T
    // FCI format: 6F (FCI Template) containing 84 (DF Name = NDEF AID)
    {
        constexpr uint8_t DESFIRE_LIGHT_FCI_FILE_NO{0x1F};
        // clang-format off
        const uint8_t fci_data[] = {
            0x6F, 0x09,                                      // FCI Template, length=9
                0x84, 0x07,                                  // DF Name tag, length=7
                    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 // NDEF AID
        };
        // clang-format on

        // Re-authenticate for FCI operations (ctx may be stale)
        a::mifare::desfire::Ev2Context ctx_fci{};
        if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx_fci)) {
            M5_LIB_LOGW("auth EV2 failed for FCI - skipping FCI write");
        } else {
            a::mifare::desfire::FileSettings fci_settings{};
            if (dfs.getFileSettingsEV2(fci_settings, DESFIRE_LIGHT_FCI_FILE_NO, ctx_fci)) {
                M5_LIB_LOGD("FCI file settings: type=%u comm=%u ar=%04X size=%u", fci_settings.file_type,
                            fci_settings.comm_mode, fci_settings.access_rights, fci_settings.file_size);

                // Change to free access and plain mode if needed
                if (fci_settings.access_rights != free_access_rights || fci_settings.comm_mode != plain_comm_mode) {
                    if (dfs.changeFileSettingsEV2Full(DESFIRE_LIGHT_FCI_FILE_NO, file_option, free_access_rights,
                                                      ctx_fci)) {
                        fci_settings.access_rights = free_access_rights;
                        fci_settings.comm_mode     = plain_comm_mode;
                        // Re-authenticate after changing settings
                        dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx_fci);
                    }
                }

                // Write FCI data
                bool fci_written = false;
                if (fci_settings.comm_mode == 0x00) {
                    fci_written = dfs.writeDataLight(DESFIRE_LIGHT_FCI_FILE_NO, 0, fci_data, sizeof(fci_data));
                } else if (fci_settings.comm_mode == 0x03) {
                    fci_written =
                        dfs.writeDataLightEV2Full(DESFIRE_LIGHT_FCI_FILE_NO, 0, fci_data, sizeof(fci_data), ctx_fci);
                } else {
                    fci_written =
                        dfs.writeDataLightEV2(DESFIRE_LIGHT_FCI_FILE_NO, 0, fci_data, sizeof(fci_data), ctx_fci);
                }

                if (fci_written) {
                    M5_LIB_LOGI("FCI file written for T4T compatibility");
                } else {
                    M5_LIB_LOGW("write FCI failed (comm %u) - continuing anyway", fci_settings.comm_mode);
                }
            } else {
                M5_LIB_LOGW("getFileSettings FCI failed - skipping FCI write");
            }
        }
    }

    // Change application to NDEF DF name after NDEF setup completes
    // NOTICE : You can only change your DF name / Fild ID ONCE!
    // Default: DF Name=A00000039656434103F015400000000B, ISO File ID=DF01
    //    NDEF: DF Name=D2760000850101, ISO File ID=E110.
    if (!ndef_aid_available) {
        a::mifare::desfire::Ev2Context ctx_rename{};
        if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx_rename)) {
            M5_LIB_LOGE("auth EV2 failed (DF name)");
            return false;
        }
        if (!dfs.setConfigurationAppNameEV2Full(NDEF_AID, sizeof(NDEF_AID), NDEF_APP_FID, ctx_rename)) {
            M5_LIB_LOGE(" setConfiguration app name failed");
            return false;
        }
    }

    // Delete TransactionMAC file (File 0Fh) if it exists
    // This is required for ISOReadBinary/ISOUpdateBinary to work on DESFire Light
    // Without this, ISO7816-4 commands fail with SW:69:85
    // Need fresh authentication because previous ctx may be stale
    constexpr uint8_t DESFIRE_LIGHT_TMAC_FILE_NO{0x0F};
    if (dfs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID)) ||
        dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
        a::mifare::desfire::Ev2Context ctx_tmac{};
        if (dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx_tmac)) {
            if (dfs.deleteTransactionMACFileEV2Full(DESFIRE_LIGHT_TMAC_FILE_NO, ctx_tmac)) {
                M5_LIB_LOGI("TMAC file deleted for ISO7816 compatibility");
            }
            // Note: Delete may fail if TMAC file doesn't exist - that's OK
        }
    }
    return true;
}

bool NDEFLayer::prepare_desfire(const uint32_t max_ndef_size)
{
    using a::mifare::desfire::NdefFormatOptions;
    using desfire::DESFIRE_CC_FILE_NO;
    using desfire::DESFIRE_DEFAULT_KEY;
    using desfire::DESFIRE_NDEF_FILE_NO;
    using type4::NDEF_AID;
    using type4::NDEF_APP_FID;
    using type4::NDEF_FILE_ID;

    if (!max_ndef_size) {
        return false;
    }
    if (!is_file_system_desfire_normal(_interface.supportsFilesystem())) {
        return false;
    }
    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(*dep);

    uint32_t free_mem{};
    uint16_t ndef_file_size{};
    if (dfs.getFreeMemory(free_mem)) {
        const uint32_t overhead = 64 + 15;  // App header + CC file
        uint32_t available      = (free_mem > overhead) ? (free_mem - overhead) : 0;
        if (free_mem >= 7936) {
            constexpr uint32_t alloc_unit = 256;
            if (available > alloc_unit) {
                // Reserve one allocation unit for the CC file on 8K+ devices.
                available -= alloc_unit;
            }
            available = (available / alloc_unit) * alloc_unit;
        }
        ndef_file_size = static_cast<uint16_t>(std::min<uint32_t>(max_ndef_size, available));
        M5_LIB_LOGV("Free memory: %u, NDEF size: %u", free_mem, ndef_file_size);
    }
    if (ndef_file_size < 32) {
        M5_LIB_LOGE("NDEF size too small: %u (free: %u)", ndef_file_size, free_mem);
        return false;
    }

    NdefFormatOptions opt{};
    opt.cc_file_no      = DESFIRE_CC_FILE_NO;
    opt.ndef_file_no    = DESFIRE_NDEF_FILE_NO;
    opt.picc_master_key = DESFIRE_DEFAULT_KEY;
    opt.app_master_key  = DESFIRE_DEFAULT_KEY;
    opt.ndef_file_size  = ndef_file_size;
    type4::FileControlTLV fct{};
    fct.tag            = 0x04;
    fct.len            = 0x06;
    fct.ndef_file_id   = NDEF_FILE_ID;
    fct.ndef_file_size = ndef_file_size;
    fct.read_access    = 0x00;
    fct.write_access   = 0x00;
    opt.cc.fctlvs.push_back(fct);

    bool picc_des_ok{};
    bool picc_iso_ok{};
    bool picc_aes_ok{};
    if (opt.picc_master_key) {
        bool ok = false;
        if (opt.auth_mode == a::mifare::desfire::AuthMode::DES || opt.auth_mode == a::mifare::desfire::AuthMode::Auto) {
            picc_des_ok = dfs.authenticateDES(0x00, opt.picc_master_key);
            if (!picc_des_ok) {
                picc_iso_ok = dfs.authenticateISO(0x00, opt.picc_master_key);
            }
            ok = picc_des_ok || picc_iso_ok;
        }
        if (!ok && (opt.auth_mode == a::mifare::desfire::AuthMode::AES ||
                    opt.auth_mode == a::mifare::desfire::AuthMode::Auto)) {
            picc_aes_ok = dfs.authenticateAES(0x00, opt.picc_master_key);
            ok          = picc_aes_ok;
        }
        if (!ok) {
            M5_LIB_LOGE("PICC master auth failed");
            return false;
        }
    }

    constexpr uint16_t app_iso_fid = NDEF_APP_FID;
    const auto* df_name            = NDEF_AID;
    constexpr uint8_t df_name_len  = sizeof(NDEF_AID);

    uint8_t key_settings2 = opt.key_settings2;
    if (opt.auth_mode == a::mifare::desfire::AuthMode::Auto && opt.picc_master_key) {
        const uint8_t base = static_cast<uint8_t>(opt.key_settings2 & 0x3F);
        if (picc_aes_ok) {
            key_settings2 = static_cast<uint8_t>(0x80 | base);
        } else if (picc_iso_ok || picc_des_ok) {
            key_settings2 = base;
        }
    }

    auto created = dfs.createApplication(opt.aid, opt.key_settings1, key_settings2, app_iso_fid, df_name, df_name_len);
    if (!created.has_value()) {
        M5_LIB_LOGE("create application failed (0x%02X)", created.error());
        return false;
    }

    if (!dfs.selectApplication(opt.aid)) {
        M5_LIB_LOGE("select application failed");
        return false;
    }
    if (opt.app_master_key) {
        bool ok = false;
        if (opt.auth_mode == a::mifare::desfire::AuthMode::Auto && opt.picc_master_key) {
            if (picc_aes_ok) {
                ok = dfs.authenticateAES(0x00, opt.app_master_key);
            } else if (picc_iso_ok) {
                ok = dfs.authenticateISO(0x00, opt.app_master_key);
            } else {
                ok = dfs.authenticateDES(0x00, opt.app_master_key);
                if (!ok) {
                    ok = dfs.authenticateISO(0x00, opt.app_master_key);
                }
            }
        } else {
            if (opt.auth_mode == a::mifare::desfire::AuthMode::DES ||
                opt.auth_mode == a::mifare::desfire::AuthMode::Auto) {
                ok = dfs.authenticateDES(0x00, opt.app_master_key);
                if (!ok) {
                    ok = dfs.authenticateISO(0x00, opt.app_master_key);
                }
            }
            if (!ok && (opt.auth_mode == a::mifare::desfire::AuthMode::AES ||
                        opt.auth_mode == a::mifare::desfire::AuthMode::Auto)) {
                ok = dfs.authenticateAES(0x00, opt.app_master_key);
            }
        }
        if (!ok) {
            M5_LIB_LOGE("prepare_desfire: app master auth failed");
            return false;
        }
    }

    if (!dfs.createStdDataFile(opt.cc_file_no, type4::CC_FILE_ID, opt.comm_mode, opt.access_rights, opt.cc_file_size)) {
        M5_LIB_LOGE("prepare_desfire: create CC file failed");
        return false;
    }

    std::vector<uint8_t> cc;
    uint16_t ndef_fid{};
    uint16_t ndef_size{};
    if (!build_desfire_cc(cc, ndef_fid, ndef_size, opt)) {
        M5_LIB_LOGE("prepare_desfire: build CC failed");
        return false;
    }
    if (!dfs.writeData(opt.cc_file_no, 0, cc.data(), static_cast<uint32_t>(cc.size()))) {
        M5_LIB_LOGE("prepare_desfire: write CC failed");
        return false;
    }

    if (!dfs.createStdDataFile(opt.ndef_file_no, ndef_fid, opt.comm_mode, opt.access_rights, ndef_size)) {
        M5_LIB_LOGE("prepare_desfire: create NDEF file failed");
        return false;
    }

    const uint8_t nlen0[2] = {0x00, 0x00};
    if (!dfs.writeData(opt.ndef_file_no, 0, nlen0, sizeof(nlen0))) {
        M5_LIB_LOGE("prepare_desfire: write NLEN failed");
        return false;
    }
    return true;
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type2::CapabilityContainer& cc)
{
    using type2::CapabilityContainer;

    cc = CapabilityContainer{};

    const uint16_t block_size = _interface.unit_size_read();
    if (!block_size || block_size > NDEF_MAX_UNIT_SIZE_READ) {
        return false;
    }

    uint8_t rx[NDEF_MAX_UNIT_SIZE_READ]{};
    uint16_t rx_len = block_size;
    uint8_t ccb     = (block_size == 4) ? TYPE2_CC_BLOCK : 0 /* 0-3 page*/;
    if (!_interface.read(rx, rx_len, ccb) || (rx_len != block_size)) {
        return false;
    }
    memcpy(cc.block, rx + ((block_size == 4) ? 0 : 12), sizeof(cc.block));

    M5_LIB_LOGV("CC2:%02X %u.%u %u %02X/%02X", cc.block[0], cc.major_version(), cc.minor_version(), cc.ndef_size(),
                cc.read_access(), cc.write_access());

    return true;
}

bool NDEFLayer::readAttributeBlock(m5::nfc::ndef::type3::AttributeBlock& ab)
{
    using type3::AttributeBlock;

    ab = AttributeBlock{};

    uint16_t block = _interface.first_user_block();
    if (block == 0xFFFF) {
        return false;
    }

    uint16_t rx_len = sizeof(ab.block);
    if (!_interface.read(ab.block, rx_len, block) || rx_len != sizeof(ab.block) ||
        ab.check_sum() != ab.calculate_check_sum()) {
        M5_LIB_LOGE("Failed to read AB actual:%u sum:%04X/%04X", rx_len, ab.check_sum(), ab.calculate_check_sum());
        return false;
    }
    M5_LIB_LOGV("AB:%02X %u/%u/%u %02X/%02X %u %04X/%04X", ab.version(), ab.max_block_to_read(),
                ab.max_block_to_write(), ab.blocks_for_ndef_storage(), ab.write_flag(), ab.access_flag(),
                ab.current_ndef_message_length(), ab.check_sum(), ab.calculate_check_sum());
    return true;
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    return is_file_system_desfire_normal(_interface.supportsFilesystem()) ? read_capability_container_type4_desfire(cc)
                                                                          : read_capability_container_type4_iso7816(cc);
}

bool NDEFLayer::read_capability_container_type4_iso7816(m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    using type4::CapabilityContainer;
    using type4::NDEF_AID;
    using type4::NDEF_APP_FID;

    cc = CapabilityContainer{};

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    FileSystem fs(*dep);
    if (!fs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID))) {
        return false;
    }
    if (!fs.selectFileIdAuto(m5::nfc::ndef::type4::CC_FILE_ID)) {
        return false;
    }
    const auto read_cc = [&fs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
        return fs.readBinary(out, offset, len);
    };
    return read_cc_common(read_cc, cc);
}

bool NDEFLayer::read_capability_container_type4_desfire(m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    using desfire::DESFIRE_CC_FILE_NO;
    using desfire::DESFIRE_LIGHT_CC_FILE_NO;
    using desfire::DESFIRE_LIGHT_DF_NAME;
    using desfire::DESFIRE_NDEF_APP_ID;
    using type4::CapabilityContainer;
    using type4::NDEF_AID;

    cc = CapabilityContainer{};

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(*dep);
    // Light
    if (is_file_system_desfire_light(_interface.supportsFilesystem())) {
        //        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
        if (!dfs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID))) {
            return false;
        }
        const auto read_cc = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return dfs.readDataLight(out, DESFIRE_LIGHT_CC_FILE_NO, offset, len);
        };
        return read_cc_common(read_cc, cc);
    }
    // DESFire
    if (!dfs.selectApplication(DESFIRE_NDEF_APP_ID)) {
        return false;
    }
    const auto read_cc = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
        return dfs.readData(out, DESFIRE_CC_FILE_NO, offset, len);
    };
    return read_cc_common(read_cc, cc);
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type5::CapabilityContainer& cc)
{
    using type5::CapabilityContainer;

    cc = CapabilityContainer{};

    auto cc_block = _interface.first_user_block();  // May be block 0
    if (cc_block == 0xFFFF) {
        return false;
    }
    uint16_t cc_block_size = _interface.unit_size_read();
    if (!cc_block_size) {
        return false;
    }
    while (cc_block_size < 8) {  // Support 8 byte CC
        cc_block_size <<= 1;
    }
    if (cc_block_size > NDEF_MAX_CC_BLOCK_SIZE) {
        return false;
    }

    // Read CC
    uint8_t rx[NDEF_MAX_CC_BLOCK_SIZE]{};
    uint16_t rx_len = cc_block_size;
    if (!_interface.read(rx, rx_len, cc_block) || rx_len != cc_block_size) {
        M5_LIB_LOGE("Failed to read CC");
        return false;
    }
    memcpy(cc.block, rx, std::min<uint16_t>(rx_len, sizeof(cc.block)));

    M5_LIB_LOGV("CC5:%02X %u.%u %u %02X/%02X %02X", cc.block[0], cc.major_version(), cc.minor_version(), cc.ndef_size(),
                cc.read_access(), cc.write_access(), cc.addtional_feature());

    return true;
}

bool NDEFLayer::writeCapabilityContainer(const m5::nfc::ndef::type5::CapabilityContainer& cc)
{
    if (!cc.size()) {
        return false;
    }
    return write_nfcv(0, cc.block, cc.size());
}

//
bool NDEFLayer::read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
                     const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();

    switch (ftag) {
        case NFCForumTag::Type2:
            return read_type2(tlvs, tagBits);
        case NFCForumTag::Type3: {
            TLV tlv{};
            if (read_type3(tlv)) {
                tlvs.emplace_back(tlv);
                return true;
            }
        } break;
        case NFCForumTag::Type4:
            return read_type4(tlvs, tag_bits_to_file_control_tag_bits(tagBits));
        case NFCForumTag::Type5:
            return read_type5(tlvs, tagBits);
        case NFCForumTag::Type1:
        default:
            break;
    }
    return false;
}

bool NDEFLayer::read_type2(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();
    type2::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to read CC or invalid CC %02X:%02X:%02X;%02X",  //
                    cc.block[0], cc.block[1], cc.block[2], cc.block[3]);
        return false;
    }

    bool ret{};
    uint16_t block      = _interface.first_user_block();
    uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    const uint16_t buf_size = _interface.user_area_size();
    if (!buf_size) {
        return false;
    }
    std::vector<uint8_t> buf(buf_size);

    // Read TLV
    uint16_t actual{buf_size};
    if (!_interface.read(buf.data(), actual, block) || actual == 0) {
        M5_LIB_LOGE("Failed to read %u %u", block, actual);
        return false;
    }

    {
        uint32_t offset{}, idx{};
        TLV tlv{};
        do {
            auto decoded = tlv.decode(buf.data() + offset, actual > offset ? actual - offset : 0);
            // Even if decoding fails, return the results up to that point and treat it as a success
            if (!decoded) {
                M5_LIB_LOGE("Failed to decode [%3u]:%02X", idx, tlv.tag());
                break;
            }
            offset += decoded;
            ++idx;
            M5_LIB_LOGD("Decoded:%u %02X", decoded, tlv.tag());

            if (contains_tag(tagBits, tlv.tag())) {
                tlvs.push_back(tlv);
            }

        } while (!tlv.isTerminatorTLV() && !tlv.isNullTLV());
        ret = true;
    }
    return ret;
}

bool NDEFLayer::read_type3(m5::nfc::ndef::TLV& tlv)
{
    using type3::AttributeBlock;
    tlv = TLV{};

    // Check AB
    AttributeBlock ab{};
    if (!readAttributeBlock(ab) || !ab.valid()) {
        M5_LIB_LOGE("Failed to read AB or invalid AB %02X:%02X:%02X;%02X",  //
                    ab.block[0], ab.block[1], ab.block[2], ab.block[3]);
        return false;
    }

    TLV tmp{Tag::Message};
    bool ret{};
    uint16_t block      = _interface.first_user_block();
    uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    // Read NDEF Records
    uint16_t buf_size       = ((ab.current_ndef_message_length() + 15) >> 4) << 4;
    const uint16_t max_size = _interface.user_area_size();
    if (buf_size > max_size) {
        M5_LIB_LOGW("Clamp NDEF length %u->%u", buf_size, max_size);
        buf_size = max_size;
    }
    std::vector<uint8_t> buf{};

    if (buf_size) {
        buf.resize(buf_size);
        uint16_t actual = buf_size;
        if (!_interface.read(buf.data(), actual, block + 1) || actual != buf_size) {
            M5_LIB_LOGE("Failed to read %u/%u", actual, buf_size);
            return false;
        }

        {
            uint16_t decoded{};
            uint16_t idx{};
            while (decoded < ab.current_ndef_message_length()) {
                Record r{};
                auto len = r.decode(buf.data() + decoded, actual - decoded);
                if (!len) {
                    M5_LIB_LOGE("Failed to decode %u", idx);
                    return false;
                }
                tmp.push_back(r);
                decoded += len;
                ++idx;
            }
        }
        tlv = tmp;
    }
    ret = true;

    return ret;
}

bool NDEFLayer::read_type4(std::vector<m5::nfc::ndef::TLV>& tlvs,
                           const m5::nfc::ndef::type4::FileControlTagBits fc_bits)
{
    return is_file_system_desfire_normal(_interface.supportsFilesystem()) ? read_type4_desfire(tlvs, fc_bits)
                                                                          : read_type4_iso7816(tlvs, fc_bits);
}

namespace {

using ReadFn  = std::function<bool(std::vector<uint8_t>& out, uint16_t offset, uint16_t len)>;
using WriteFn = std::function<bool(uint16_t offset, const uint8_t* data, uint16_t len)>;

const m5::nfc::ndef::TLV* find_message_tlv(const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    for (auto&& tlv : tlvs) {
        if (tlv.isMessageTLV()) {
            return &tlv;
        }
    }
    return nullptr;
}

const m5::nfc::ndef::TLV* find_proprietary_tlv(const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    for (auto&& tlv : tlvs) {
        if (tlv.tag() == m5::nfc::ndef::Tag::Proprietary) {
            return &tlv;
        }
    }
    return nullptr;
}

const m5::nfc::ndef::TLV* find_tlv_for_fctlv(const std::vector<m5::nfc::ndef::TLV>& tlvs,
                                             const m5::nfc::ndef::type4::FileControlTLV& fctlv)
{
    using type4::FileControlTag;

    switch (fctlv.fctag()) {
        case FileControlTag::Message:
            return find_message_tlv(tlvs);
        case FileControlTag::Proprietary:
            return find_proprietary_tlv(tlvs);
        default:
            return nullptr;
    }
}

bool build_ndef_payload(const m5::nfc::ndef::TLV& src, const uint32_t user_size, const uint16_t ndef_file_size,
                        std::vector<uint8_t>& payload)
{
    if (!src.isMessageTLV()) {
        return false;
    }
    const uint32_t record_size =
        std::accumulate(src.records().begin(), src.records().end(), 0U,
                        [](uint32_t acc, const m5::nfc::ndef::Record& r) { return acc + r.required(); });
    if (record_size == 0) {
        M5_LIB_LOGE("recodrd size 0");
        return false;
    }
    if (ndef_file_size && ndef_file_size < 2) {
        M5_LIB_LOGE("ndef_file_size too small");
        return false;
    }
    if (ndef_file_size && record_size > (ndef_file_size - 2)) {
        M5_LIB_LOGE("over size");
        return false;
    }
    const uint32_t total_size = record_size + 2;  // NLEN + payload
    if (user_size && total_size > user_size) {
        M5_LIB_LOGE("over size 2");
        return false;
    }

    std::vector<uint8_t> msg{};
    msg.resize(record_size);
    uint32_t offset{};
    for (auto&& r : src.records()) {
        auto len = r.encode(msg.data() + offset, record_size - offset);
        if (!len) {
            M5_LIB_LOGE("decode error");
            return false;
        }
        offset += len;
    }

    const uint16_t nlen      = static_cast<uint16_t>(msg.size());
    const uint8_t nlen_be[2] = {static_cast<uint8_t>(nlen >> 8), static_cast<uint8_t>(nlen & 0xFF)};
    payload.clear();
    payload.reserve(total_size);
    payload.insert(payload.end(), nlen_be, nlen_be + sizeof(nlen_be));
    payload.insert(payload.end(), msg.begin(), msg.end());
    return true;
}

bool write_chunks(const WriteFn& write, const std::vector<uint8_t>& data, const uint16_t max_lc)
{
    if (data.size() > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    uint16_t offset = 0;
    while (offset < data.size()) {
        const uint16_t remaining = static_cast<uint16_t>(data.size() - offset);
        const uint16_t chunk     = std::min<uint16_t>(remaining, max_lc);
        if (!write(offset, data.data() + offset, chunk)) {
            return false;
        }
        offset = static_cast<uint16_t>(offset + chunk);
    }
    return true;
}

bool read_type4_message(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::type4::CapabilityContainer& cc,
                        const m5::nfc::ndef::type4::FileControlTLV& fctlv, const ReadFn& read_message)
{
    std::vector<uint8_t> head;
    if (!read_message(head, 0, 2) || head.size() < 2) {
        return false;
    }
    const uint16_t nlen = (static_cast<uint16_t>(head[0]) << 8) | head[1];
    M5_LIB_LOGD("Type4 NLEN:%u", nlen);
    if (nlen == 0) {
        tlvs.emplace_back(m5::nfc::ndef::Tag::Message);
        return true;
    }
    if (fctlv.ndef_file_size && nlen > (fctlv.ndef_file_size - 2)) {
        return false;
    }

    std::vector<uint8_t> buf;
    buf.reserve(nlen);
    uint16_t offset       = 0;
    const uint16_t max_le = cc.mle ? std::min<uint16_t>(cc.mle, 32) : 0x00FF;
    while (offset < nlen) {
        const uint16_t remaining = static_cast<uint16_t>(nlen - offset);
        const uint16_t chunk     = std::min<uint16_t>(remaining, max_le);
        std::vector<uint8_t> part;
        if (!read_message(part, static_cast<uint16_t>(2 + offset), chunk) || part.size() < chunk) {
            return false;
        }
        buf.insert(buf.end(), part.begin(), part.begin() + chunk);
        offset = static_cast<uint16_t>(offset + chunk);
    }
    if (buf.size() < nlen) {
        return false;
    }

    m5::nfc::ndef::TLV msg{m5::nfc::ndef::Tag::Message};
    uint16_t decoded{};
    while (decoded < nlen) {
        m5::nfc::ndef::Record r{};
        auto len = r.decode(buf.data() + decoded, nlen - decoded);
        if (!len) {
            return false;
        }
        msg.push_back(r);
        decoded += len;
    }
    tlvs.push_back(msg);
    return true;
}

bool read_type4_proprietary(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::type4::CapabilityContainer& cc,
                            const m5::nfc::ndef::type4::FileControlTLV& fctlv, const ReadFn& read_proprietary)
{
    std::vector<uint8_t> data;
    const uint16_t size = fctlv.ndef_file_size;
    if (size == 0) {
        return true;
    }
    data.reserve(size);
    uint16_t offset       = 0;
    const uint16_t max_le = cc.mle ? std::min<uint16_t>(cc.mle, 32) : 0x00FF;
    while (offset < size) {
        const uint16_t remaining = static_cast<uint16_t>(size - offset);
        const uint16_t chunk     = std::min<uint16_t>(remaining, max_le);
        std::vector<uint8_t> part;
        if (!read_proprietary(part, offset, chunk) || part.size() < chunk) {
            return false;
        }
        data.insert(data.end(), part.begin(), part.begin() + chunk);
        offset = static_cast<uint16_t>(offset + chunk);
    }
    m5::nfc::ndef::TLV tlv{m5::nfc::ndef::Tag::Proprietary};
    tlv.payload() = std::move(data);
    tlvs.push_back(tlv);
    return true;
}

}  // namespace

bool NDEFLayer::read_type4_desfire(std::vector<m5::nfc::ndef::TLV>& tlvs,
                                   const m5::nfc::ndef::type4::FileControlTagBits fc_bits)
{
    using desfire::DESFIRE_LIGHT_DF_NAME;
    using desfire::DESFIRE_LIGHT_NDEF_FILE_NO;
    using desfire::DESFIRE_NDEF_APP_ID;
    using desfire::DESFIRE_NDEF_FILE_NO;
    using type4::CapabilityContainer;
    using type4::FileControlTag;
    using type4::NDEF_AID;

    tlvs.clear();

    CapabilityContainer cc{};
    if (!read_capability_container_type4_desfire(cc) || !cc.valid()) {
        return false;
    }

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(*dep);
    ReadFn read_message{};

    // Light
    if (is_file_system_desfire_light(_interface.supportsFilesystem())) {
        // if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
        if (!dfs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID))) {
            return false;
        }
        read_message = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return dfs.readDataLight(out, DESFIRE_LIGHT_NDEF_FILE_NO, offset, len);
        };
    }
    // DESFire
    else {
        if (!dfs.selectApplication(DESFIRE_NDEF_APP_ID)) {
            return false;
        }
        read_message = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return dfs.readData(out, DESFIRE_NDEF_FILE_NO, offset, len);
        };
    }

    for (auto&& fctlv : cc.fctlvs) {
        if (!type4::contains_file_control_tag(fc_bits, fctlv.fctag())) {
            continue;
        }

        if (fctlv.fctag() == type4::FileControlTag::Proprietary) {
            if (!read_type4_proprietary(tlvs, cc, fctlv, read_message)) {
                return false;
            }
        } else if (fctlv.fctag() == type4::FileControlTag::Message) {
            if (!read_type4_message(tlvs, cc, fctlv, read_message)) {
                return false;
            }
        } else {
            M5_LIB_LOGE("Illegal type? %02X", fctlv.fctag());
            return false;
        }
    }
    return true;
}

bool NDEFLayer::read_type4_iso7816(std::vector<m5::nfc::ndef::TLV>& tlvs,
                                   const m5::nfc::ndef::type4::FileControlTagBits fc_bits)
{
    using type4::CapabilityContainer;
    using type4::NDEF_AID;

    tlvs.clear();

    CapabilityContainer cc{};
    if (!read_capability_container_type4_iso7816(cc) || !cc.valid()) {
        return false;
    }

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    FileSystem fs(*dep);
    const bool selected_df = fs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID));
    if (!selected_df) {
        return false;
    }

    for (auto&& fctlv : cc.fctlvs) {
        if (!type4::contains_file_control_tag(fc_bits, fctlv.fctag())) {
            continue;
        }
        if (!fs.selectFileIdAuto(fctlv.ndef_file_id)) {
            return false;
        }
        const ReadFn read_message = [&fs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return fs.readBinary(out, offset, len);
        };
        if (fctlv.fctag() == type4::FileControlTag::Proprietary) {
            if (!read_type4_proprietary(tlvs, cc, fctlv, read_message)) {
                return false;
            }
        } else if (fctlv.fctag() == type4::FileControlTag::Message) {
            if (!read_type4_message(tlvs, cc, fctlv, read_message)) {
                return false;
            }
        } else {
            M5_LIB_LOGE("Illegal type? %02X", fctlv.fctag());
            return false;
        }
    }

    return true;
}

bool NDEFLayer::read_type5(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits)
{
    tlvs.clear();
    type5::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to read CC or invalid CC %02X:%02X:%02X;%02X",  //
                    cc.block[0], cc.block[1], cc.block[2], cc.block[3]);
        return false;
    }

    // Use CC's ndef_size to determine read size (ndef_size includes CC)
    const uint16_t user_area_size = _interface.user_area_size();
    const uint16_t ndef_size      = cc.ndef_size();
    if (ndef_size == 0 || ndef_size > user_area_size) {
        M5_LIB_LOGE("Invalid ndef_size %u (user_area:%u)", ndef_size, user_area_size);
        return false;
    }

    uint32_t offset = cc.size();
    if (offset >= ndef_size) {
        return true;
    }

    uint32_t idx{};
    while (offset < ndef_size) {
        uint8_t tag{};
        if (!read_nfcv(&tag, offset, 1)) {
            return false;
        }

        // M5_LIB_LOGE("  Tag:%02X", tag);
        if (!is_valid_tag(tag)) {
            M5_LIB_LOGW("Invalid tag %02X at offset:%u, stop parsing", tag, offset);
            break;  // Return the TLVs up to this point
        }

        // Terminator TLV (single byte)
        if (is_terminator_tag(tag)) {
            TLV tlv{Tag::Terminator};
            if (contains_tag(tagBits, tlv.tag())) {
                tlvs.push_back(tlv);
            }
            break;
        }
        // Null TLV (single byte)
        if (tag == m5::stl::to_underlying(Tag::Null)) {
            break;
        }

        uint8_t len1{};
        if (offset + 1 >= ndef_size || !read_nfcv(&len1, offset + 1, 1)) {
            return false;
        }
        uint16_t payload_len{};
        uint8_t len_bytes{1};
        if (len1 == 0xFF) {
            uint8_t len2[2]{};
            if (offset + 3 >= ndef_size || !read_nfcv(len2, offset + 2, 2)) {
                return false;
            }
            payload_len = ((uint16_t)len2[0] << 8) | len2[1];
            len_bytes   = 3;
        } else {
            payload_len = len1;
        }

        const uint32_t total_len = 1 + len_bytes + payload_len;
        if (offset + total_len > ndef_size) {
            M5_LIB_LOGE("TLV out of range offset:%u len:%u ndef:%u", offset, total_len, ndef_size);
            return false;
        }

        std::vector<uint8_t> buf(total_len);
        if (!read_nfcv(buf.data(), offset, total_len)) {
            return false;
        }

        TLV tlv{};
        // M5_LIB_LOGE("---> Tag:%02X Payload:", tag);
        // m5::utility::log::dump(buf.data(), total_len, false);

        auto decoded = tlv.decode(buf.data(), total_len);
        // Even if decoding fails, return the results up to that point and treat it as a success
        if (!decoded) {
            M5_LIB_LOGW("Failed to decode [%3u]:%02X", idx, tlv.tag());
            break;
        }
        offset += decoded;
        ++idx;
        M5_LIB_LOGV("Decoded:%u %02X", decoded, tlv.tag());

        if (contains_tag(tagBits, tlv.tag())) {
            tlvs.push_back(tlv);
        }

        if (tlv.isTerminatorTLV() || tlv.isNullTLV()) {
            break;
        }
    }

    return true;
}

bool NDEFLayer::read_nfcv(uint8_t* rx, const uint16_t offset, const uint16_t len)
{
    if (!rx || !len) {
        return false;
    }

    const uint16_t block_size = _interface.unit_size_read();
    if (!block_size || block_size > NDEF_MAX_UNIT_SIZE_READ) {
        return false;
    }

    const uint16_t first_block = _interface.first_user_block();
    const uint16_t start_block = first_block + offset / block_size;
    const uint8_t start_offset = offset % block_size;
    const uint16_t end_byte    = offset + len - 1;
    const uint16_t end_block   = first_block + end_byte / block_size;

    if (end_block > _interface.last_user_block()) {
        return false;
    }

    uint16_t written = 0;
    for (uint16_t block = start_block; block <= end_block; ++block) {
        uint8_t rbuf[NDEF_MAX_UNIT_SIZE_READ]{};
        uint16_t rlen = block_size;
        if (!_interface.read(rbuf, rlen, block) || rlen != block_size) {
            return false;
        }

        const uint8_t blk_start = (block == start_block) ? start_offset : 0;
        const uint8_t blk_end   = (block == end_block) ? (end_byte % block_size) : (block_size - 1);
        const uint8_t copy_len  = blk_end - blk_start + 1;

        memcpy(rx + written, rbuf + blk_start, copy_len);
        written += copy_len;
    }
    return written == len;
}

bool NDEFLayer::write_nfcv(const uint16_t offset, const uint8_t* tx, const uint16_t len)
{
    if (!tx || !len) {
        return false;
    }

    const uint16_t block_size = _interface.unit_size_write();
    if (!block_size || block_size > NDEF_MAX_UNIT_SIZE_READ) {
        return false;
    }

    const uint16_t first_block = _interface.first_user_block();
    const uint16_t start_block = first_block + offset / block_size;
    const uint8_t start_offset = offset % block_size;
    const uint16_t end_byte    = offset + len - 1;
    const uint16_t end_block   = first_block + end_byte / block_size;

    if (end_block > _interface.last_user_block()) {
        return false;
    }

    uint16_t src_offset = 0;
    for (uint16_t block = start_block; block <= end_block; ++block) {
        const uint8_t blk_start = (block == start_block) ? start_offset : 0;
        const uint8_t blk_end   = (block == end_block) ? (end_byte % block_size) : (block_size - 1);
        const uint8_t copy_len  = blk_end - blk_start + 1;

        uint8_t wbuf[NDEF_MAX_UNIT_SIZE_READ]{};

        // Read-modify-write for partial blocks
        if (blk_start != 0 || blk_end != block_size - 1) {
            uint16_t rlen = block_size;
            if (!_interface.read(wbuf, rlen, block) || rlen != block_size) {
                return false;
            }
        }

        memcpy(wbuf + blk_start, tx + src_offset, copy_len);

        if (!_interface.write(block, wbuf, block_size)) {
            return false;
        }
        src_offset += copy_len;
    }
    return src_offset == len;
}

//

bool NDEFLayer::write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    if (!tlvs.empty()) {
        switch (ftag) {
            case NFCForumTag::Type2:
                return write_type2(tlvs, keep);
            case NFCForumTag::Type3:
                return write_type3(tlvs.front());
            case NFCForumTag::Type4:
                return write_type4(tlvs);
            case NFCForumTag::Type5:
                return write_type5(tlvs, keep);
            case NFCForumTag::Type1:
            default:
                break;
        }
    }
    return false;
}

bool NDEFLayer::write_type2(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    bool ret{};
    const uint32_t user_size = _interface.user_area_size();

    if (tlvs.empty()) {
        return false;
    }

    std::vector<TLV> tmp{};
    if (keep) {
        // Maintain TLVs that must not be removed
        if (!read_type2(tmp, tagBitsAll)) {
            return false;
        }
        tmp = merge_tlv(tmp, tlvs);
    } else {
        // Overwirte
        tmp = tlvs;
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGV("Encoded size:%u", encoded_size);
    if (encoded_size > user_size) {
        M5_LIB_LOGE("Not enough area %u/%u", encoded_size, user_size);
        return false;
    }

    // Encode
    std::vector<uint8_t> buf(encoded_size);

    uint32_t offset{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        const auto esz = m.encode(buf.data() + offset, encoded_size - offset);
        M5_LIB_LOGV("   [%3u] Tag:%02X %u %u", idx, m.tag(), esz, m.required());
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            return false;
        }
        offset += esz;
        ++idx;
    }
    if (offset > encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        return false;
    }

    // Write
    // M5_LIB_LOGE(">>>>ndef write %u %u", _interface.first_user_block(), encoded_size);
    ret = _interface.write(_interface.first_user_block(), buf.data(), encoded_size);

    return ret;
}

bool NDEFLayer::write_type3(const m5::nfc::ndef::TLV& tlv)
{
    using type3::AttributeBlock;

    AttributeBlock ab{};
    bool ret{};

    if (!tlv.isMessageTLV()) {
        return false;
    }

    // Read AB
    (void)readAttributeBlock(ab);

    uint16_t first_block = _interface.first_user_block();
    uint16_t last_block  = _interface.last_user_block();
    if (first_block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    uint16_t user_size   = _interface.user_area_size();
    uint32_t record_size = std::accumulate(tlv.records().begin(), tlv.records().end(), 0U,
                                           [](uint32_t acc, const Record& r) { return acc + r.required(); });
    if (record_size + 16 > user_size) {
        M5_LIB_LOGE("Not enough area %u/%u", record_size + 16, user_size);
        return false;
    }

    // Encode
    std::vector<uint8_t> buf(record_size);

    uint32_t idx{};
    uint32_t encoded{};
    for (auto&& r : tlv.records()) {
        auto len = r.encode(buf.data() + encoded, record_size - encoded);
        if (!len) {
            M5_LIB_LOGE("Failed to encode %u", idx);
            return false;
        }
        encoded += len;
        ++idx;
    }

    // Write
    {
        if (!ab.valid()) {
            ab.version(AttributeBlock::DEFAULT_VERSION);
            ab.max_block_to_read(_interface.maximum_read_blocks());
            ab.max_block_to_write(_interface.maximum_write_blocks());
            ab.blocks_for_ndef_storage(last_block - first_block + 1 - 1 /* AB */);
            ab.access_flag(AttributeBlock::AccessFlag::ReadWrite);
        }
        ab.write_flag(AttributeBlock::WriteFlag::InProgress);  // protect
        ab.current_ndef_message_length(record_size);
        ab.update_check_sum();

        // 1) Write AB (In progress)
        if (!_interface.write(first_block, ab.block, sizeof(ab.block))) {
            return false;
        }
        // 2) Write records
        if (!_interface.write(first_block + 1, buf.data(), record_size)) {
            return false;
        }
        // 3) Write AB again (Done)
        ab.write_flag(AttributeBlock::WriteFlag::Done);  // done
        ab.update_check_sum();
        if (!_interface.write(first_block, ab.block, sizeof(ab.block))) {
            return false;
        }
        ret = true;
    }

    return ret;
}

bool NDEFLayer::write_type4(const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    using type4::CapabilityContainer;

    if (tlvs.empty()) {
        return false;
    }
    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    CapabilityContainer cc{};
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to readCapabilityContainer");
        return false;
    }
    return is_file_system_desfire_normal(_interface.supportsFilesystem()) ? write_type4_desfire(tlvs, cc, *dep)
                                                                          : write_type4_iso7816(tlvs, cc, *dep);
}

bool NDEFLayer::write_type4_desfire(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                                    isodep::IsoDEP& dep)
{
    (void)cc;

    using desfire::DESFIRE_DEFAULT_KEY;
    using desfire::DESFIRE_LIGHT_DF_NAME;
    using desfire::DESFIRE_LIGHT_NDEF_FILE_NO;
    using type4::NDEF_AID;

    const TLV* src = find_message_tlv(tlvs);
    if (!src) {
        return false;
    }

    const uint32_t user_size = _interface.user_area_size();
    std::vector<uint8_t> payload;
    if (!build_ndef_payload(*src, user_size, 0, payload)) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(dep);

    // Light
    if (is_file_system_desfire_light(_interface.supportsFilesystem())) {
        //        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
        if (!dfs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID))) {
            return false;
        }
        return dfs.writeDataLight(desfire::DESFIRE_LIGHT_NDEF_FILE_NO, 0, payload.data(),
                                  static_cast<uint32_t>(payload.size()));
    }

    // DESFire
    if (!dfs.selectApplication(desfire::DESFIRE_NDEF_APP_ID)) {
        return false;
    }
    return dfs.writeData(desfire::DESFIRE_NDEF_FILE_NO, 0, payload.data(), static_cast<uint32_t>(payload.size()));
}

bool NDEFLayer::write_type4_iso7816(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                                    isodep::IsoDEP& dep)
{
    using type4::NDEF_AID;

    FileSystem fs(dep);
    const bool selected_df = fs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID));
    if (!selected_df) {
        M5_LIB_LOGE("selectDF failed");
        return false;
    }

    const uint32_t user_size   = _interface.user_area_size();
    const uint16_t max_lc      = cc.mlc ? std::min<uint16_t>(cc.mlc, 32) : 0x00FF;
    const WriteFn write_binary = [&fs](const uint16_t offset, const uint8_t* data, const uint16_t len) {
        return fs.updateBinary(offset, data, len);
    };

    for (auto&& fctlv : cc.fctlvs) {
        const TLV* src = find_tlv_for_fctlv(tlvs, fctlv);
        if (!src) {
            continue;
        }

        const bool selected_file = fs.selectFileIdAuto(fctlv.ndef_file_id);
        if (!selected_file) {
            M5_LIB_LOGE("select file failed");
            return false;
        }

        if (fctlv.fctag() == type4::FileControlTag::Proprietary) {
            const auto& payload = src->payload();
            if (fctlv.ndef_file_size && payload.size() > fctlv.ndef_file_size) {
                return false;
            }
            if (!write_chunks(write_binary, payload, max_lc)) {
                return false;
            }
            continue;
        }

        if (!src->isMessageTLV()) {
            continue;
        }

        std::vector<uint8_t> payload;
        if (!build_ndef_payload(*src, user_size, fctlv.ndef_file_size, payload)) {
            M5_LIB_LOGW("Not enough area %u/%u", fctlv.ndef_file_size, user_size);
            return false;
        }
        if (!write_chunks(write_binary, payload, max_lc)) {
            M5_LIB_LOGE("write_chunk failed");
            return false;
        }
    }
    return true;
}

bool NDEFLayer::write_type5(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    const uint32_t user_size = _interface.user_area_size();

    if (tlvs.empty()) {
        return false;
    }

    // Read CC
    type5::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc)) {
        return false;
    }

    std::vector<TLV> tmp{};
    if (keep) {
        if (cc.valid()) {
            // Read all TLV and merge
            if (read_type5(tmp, tagBitsAll)) {
                tmp = merge_tlv(tmp, tlvs);
            } else {
                // Overwrite if invalid NDEF
                tmp = tlvs;
            }
        } else {
            // Overwrite if CC is invalid
            tmp = tlvs;
        }
    } else {
        tmp = tlvs;  // Overwrite
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGV("Encoded size:%u", encoded_size);

    // Make CC
    if (!cc.valid()) {
        cc.block[0] = (user_size > CC4_MAX_NDEF_LENGTH) ? MAGIC_NO_CC8 : MAGIC_NO_CC4;
        cc.major_version(NDEF_MAJOR_VERSION);
        cc.minor_version(NDEF_MINOR_VERSION);
        cc.ndef_size(user_size);
        cc.read_access(ACCESS_FREE);
        cc.write_access(ACCESS_FREE);
        cc.addtional_feature(0);
    }

    uint32_t buf_size = encoded_size + cc.size();
    if (buf_size > cc.ndef_size()) {
        M5_LIB_LOGE("Not enough area %u/%u/%u", encoded_size, cc.ndef_size(), _interface.user_area_size());
        return false;
    }

    // Write CC first
    uint32_t offset{};
    if (!cc.size()) {
        return false;
    }
    if (!write_nfcv(0, cc.block, cc.size())) {
        return false;
    }
    offset += cc.size();

    // Encode and write each TLV to avoid large heap buffers
    std::vector<uint8_t> buf{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        // M5_LIB_LOGE("Tag:%02x %u", m.tag(), m.required());
        const uint32_t esz = m.required();
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            return false;
        }
        if (esz > 0xFFFF || offset + esz > 0xFFFF) {
            M5_LIB_LOGE("TLV too large %u (offset:%u)", esz, offset);
            return false;
        }
        if (offset + esz > user_size) {
            M5_LIB_LOGE("Not enough area %u/%u", offset + esz, user_size);
            return false;
        }
        buf.assign(esz, 0);
        const auto written = m.encode(buf.data(), esz);
        M5_LIB_LOGD("   [%3u] Tag:%02X %u %u", idx, m.tag(), written, esz);
        if (!written || written != esz) {
            M5_LIB_LOGE("encode failed %u %02X %u/%u", idx, m.tag(), written, esz);
            return false;
        }
        if (!write_nfcv(offset, buf.data(), static_cast<uint16_t>(esz))) {
            return false;
        }
        offset += esz;
        ++idx;
    }
    if (offset > buf_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, buf_size);
        return false;
    }

    return true;
}

/*
  Remove only the NULL, Message, and Terminator TLVs, then add new TLVs
  (Lock, Memory and Proprietary fields are retained)
 */
std::vector<m5::nfc::ndef::TLV> NDEFLayer::merge_tlv(std::vector<m5::nfc::ndef::TLV>& old_tlvs,
                                                     const std::vector<m5::nfc::ndef::TLV>& tlvs)
{
    // Remove Null,Message,and Terminator (Keep Lock,Memory,Proprietary)
    auto it = std::remove_if(old_tlvs.begin(), old_tlvs.end(), [](const TLV& m) {  //
        return m.tag() == Tag::Null || m.tag() == Tag::Message || m.tag() == Tag::Terminator;
    });
    old_tlvs.erase(it, old_tlvs.end());

    // Insert argument before Proprietary TLV
    it = std::find_if(old_tlvs.begin(), old_tlvs.end(), [](const TLV& m) { return m.tag() == Tag::Proprietary; });
    old_tlvs.insert(it, tlvs.begin(), tlvs.end());

    // Append terminator
    if (old_tlvs.empty() || old_tlvs.back().tag() != Tag::Terminator) {
        old_tlvs.push_back(TLV(Tag::Terminator));
    }
    return old_tlvs;
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
