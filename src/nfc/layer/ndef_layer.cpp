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
    constexpr uint16_t kCcLen         = 0x000F;
    constexpr uint8_t kMappingVersion = 0x20;
    constexpr uint16_t kMle           = 0x003A;
    constexpr uint16_t kMlc           = 0x0034;

    out.clear();
    if (!ndef_fid || !ndef_size) {
        return false;
    }
    out.reserve(kCcLen);
    out.push_back(static_cast<uint8_t>((kCcLen >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(kCcLen & 0xFF));
    out.push_back(kMappingVersion);
    out.push_back(static_cast<uint8_t>((kMle >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(kMle & 0xFF));
    out.push_back(static_cast<uint8_t>((kMlc >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(kMlc & 0xFF));
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

constexpr int kAccessDenied = -1;
constexpr int kAccessFree   = -2;

int required_key_no_from_access_rights(const uint16_t access_rights)
{
    const uint8_t write_key = (access_rights >> 8) & 0x0F;  // Write
    const uint8_t rw_key    = (access_rights >> 4) & 0x0F;  // Read/Write
    if (write_key == 0x0E) {
        return kAccessFree;
    }
    if (write_key != 0x0F) {
        return write_key;
    }
    if (rw_key == 0x0E) {
        return kAccessFree;
    }
    if (rw_key != 0x0F) {
        return rw_key;
    }
    return kAccessDenied;
}

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
            // Unformatted DESFire returns success
            if (_interface.supportsFilesystem() & (FILE_SYSTEM_DESFIRE | FILE_SYSTEM_DESFIRE_LIGHT)) {
                M5_LIB_LOGE(">>>> DESFire not in NDEF format");
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
    using type4::DESFIRE_DEFAULT_KEY;
    using type4::DESFIRE_LIGHT_CC_FILE_NO;
    using type4::DESFIRE_LIGHT_DF_NAME;
    using type4::DESFIRE_LIGHT_NDEF_FILE_NO;
    using type4::DESFIRE_LIGHT_NDEF_FILE_SIZE;
    using type4::NDEF_FILE_ID;

    if (!(_interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE_LIGHT)) {
        return false;
    }
    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(*dep);
    if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
        M5_LIB_LOGE("prepare_desfire_light: select DF failed");
        return false;
    }

    // Already renamed to AN11004 FIDs?
    if (!dfs.selectFileIdAuto(type4::CC_FILE_ID)) {
        M5_LIB_LOGE("prepare_desfire_light: select CC(E103) failed -> rename");
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
            M5_LIB_LOGE("prepare_desfire_light: auth EV2 failed");
            return false;
        }
        if (!dfs.setConfigurationFileRenaming(cc_rename, &ndef_rename, ctx)) {
            M5_LIB_LOGE("prepare_desfire_light: setConfiguration rename failed");
            return false;
        }
    } else {
        M5_LIB_LOGV("prepare_desfire_light: CC(E103) already exists");
    }

    a::mifare::desfire::Ev2Context ctx{};
    if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx)) {
        M5_LIB_LOGE("prepare_desfire_light: auth EV2 failed (write)");
        return false;
    }

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

    constexpr uint16_t kFreeAccessRights = 0xEE30;
    constexpr uint8_t kPlainCommMode     = 0x00;
    if (cc_settings.access_rights != kFreeAccessRights || cc_settings.comm_mode != kPlainCommMode) {
        if (cc_settings.comm_mode != kPlainCommMode) {
            M5_LIB_LOGE("prepare_desfire_light: CC comm_mode %u not supported", cc_settings.comm_mode);
            return false;
        }
        const uint8_t file_option = (kPlainCommMode & 0x03);
        if (!dfs.changeFileSettings(DESFIRE_LIGHT_CC_FILE_NO, file_option, kFreeAccessRights)) {
            M5_LIB_LOGE("prepare_desfire_light: changeFileSettings CC failed");
            return false;
        }
        cc_settings.access_rights = kFreeAccessRights;
        cc_settings.comm_mode     = kPlainCommMode;
    }
    if (ndef_settings.access_rights != kFreeAccessRights || ndef_settings.comm_mode != kPlainCommMode) {
        if (ndef_settings.comm_mode != kPlainCommMode) {
            M5_LIB_LOGE("prepare_desfire_light: NDEF comm_mode %u not supported", ndef_settings.comm_mode);
            return false;
        }
        const uint8_t file_option = (kPlainCommMode & 0x03);
        if (!dfs.changeFileSettings(DESFIRE_LIGHT_NDEF_FILE_NO, file_option, kFreeAccessRights)) {
            M5_LIB_LOGE("prepare_desfire_light: changeFileSettings NDEF failed");
            return false;
        }
        ndef_settings.access_rights = kFreeAccessRights;
        ndef_settings.comm_mode     = kPlainCommMode;
    }

    auto write_with_mode = [&dfs, &ctx](const uint8_t file_no, const uint8_t* data, const uint32_t data_len,
                                        const uint8_t comm_mode) {
        switch (comm_mode) {
            case 0x00:
                return dfs.writeDataLight(file_no, 0, data, data_len);
            case 0x01:
                return dfs.writeDataEV2Mac(file_no, 0, data, data_len, ctx);
            case 0x03:
                return dfs.writeDataEV2Full(file_no, 0, data, data_len, ctx);
            default:
                return false;
        }
    };

    std::vector<uint8_t> cc;
    if (!build_type4_cc(cc, NDEF_FILE_ID, DESFIRE_LIGHT_NDEF_FILE_SIZE, 0x00, 0x00)) {
        return false;
    }
    const int cc_key = required_key_no_from_access_rights(cc_settings.access_rights);
    if (cc_key == kAccessDenied ||
        (cc_key >= 0 && !dfs.authenticateEV2First(static_cast<uint8_t>(cc_key), DESFIRE_DEFAULT_KEY, ctx))) {
        M5_LIB_LOGE("prepare_desfire_light: auth EV2 failed (CC key %d)", cc_key);
        return false;
    }
    if (!write_with_mode(DESFIRE_LIGHT_CC_FILE_NO, cc.data(), static_cast<uint32_t>(cc.size()),
                         cc_settings.comm_mode)) {
        M5_LIB_LOGE("prepare_desfire_light: write CC failed (comm %u)", cc_settings.comm_mode);
        return false;
    }

    const uint8_t nlen0[2] = {0x00, 0x00};
    const int ndef_key     = required_key_no_from_access_rights(ndef_settings.access_rights);
    if (ndef_key == kAccessDenied ||
        (ndef_key >= 0 && !dfs.authenticateEV2First(static_cast<uint8_t>(ndef_key), DESFIRE_DEFAULT_KEY, ctx))) {
        M5_LIB_LOGE("prepare_desfire_light: auth EV2 failed (NDEF key %d)", ndef_key);
        return false;
    }
    if (!write_with_mode(DESFIRE_LIGHT_NDEF_FILE_NO, nlen0, sizeof(nlen0), ndef_settings.comm_mode)) {
        M5_LIB_LOGE("prepare_desfire_light: write NLEN failed (comm %u)", ndef_settings.comm_mode);
        return false;
    }
    M5_LIB_LOGE("prepare_desfire_light: done");
    return true;
}

bool NDEFLayer::readCapabilityContainer(m5::nfc::ndef::type2::CapabilityContainer& cc)
{
    using type2::CapabilityContainer;

    cc = CapabilityContainer{};

    const uint16_t block_size = _interface.unit_size_read();

    uint8_t rx[block_size]{};
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
    return _interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE ? read_capability_container_type4_desfire(cc)
                                                                 : read_capability_container_type4_iso7816(cc);
}

bool NDEFLayer::read_capability_container_type4_iso7816(m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    using type4::CapabilityContainer;
    using type4::NDEF_AID;

    cc = CapabilityContainer{};

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    FileSystem fs(*dep);
    if (!fs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID))) {
        return false;
    }
    const bool selected_cc = fs.selectFileIdAuto(m5::nfc::ndef::type4::CC_FILE_ID);
    if (!selected_cc) {
        return false;
    }

    const auto read_cc = [&fs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
        return fs.readBinary(out, offset, len);
    };
    return read_cc_common(read_cc, cc);
}

bool NDEFLayer::read_capability_container_type4_desfire(m5::nfc::ndef::type4::CapabilityContainer& cc)
{
    using type4::CapabilityContainer;
    using type4::DESFIRE_CC_FILE_NO;
    using type4::DESFIRE_LIGHT_CC_FILE_NO;
    using type4::DESFIRE_LIGHT_DF_NAME;
    using type4::DESFIRE_NDEF_APP_ID;

    cc = CapabilityContainer{};

    auto* dep = _interface.isoDEP();
    if (!dep) {
        return false;
    }

    a::mifare::desfire::DESFireFileSystem dfs(*dep);
    const bool is_light = _interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE_LIGHT;
    if (is_light) {
        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
            return false;
        }
        const auto read_cc = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return dfs.readData(out, DESFIRE_LIGHT_CC_FILE_NO, offset, len);
        };
        return read_cc_common(read_cc, cc);
    }

    if (!dfs.selectApplication(DESFIRE_NDEF_APP_ID)) {
        return false;
    }
    const auto read_cc = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
        return dfs.readData(out, DESFIRE_CC_FILE_NO, offset, len);
    };
    if (!read_cc_common(read_cc, cc)) {
        return false;
    }
    return true;
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

    // Read CC
    uint8_t rx[cc_block_size]{};
    uint16_t rx_len = sizeof(rx);
    if (!_interface.read(rx, rx_len, cc_block) || rx_len != cc_block_size) {
        return false;
    }
    memcpy(cc.block, rx, std::min<uint16_t>(rx_len, sizeof(cc.block)));

    M5_LIB_LOGV("CC5:%02X %u.%u %u %02X/%02X %02X", cc.block[0], cc.major_version(), cc.minor_version(), cc.ndef_size(),
                cc.read_access(), cc.write_access(), cc.addtional_feature());

    return true;
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
    uint8_t* buf{};
    uint16_t block      = _interface.first_user_block();
    uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    const uint16_t buf_size = _interface.user_area_size();

    buf = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }

    // Read TLV
    uint16_t actual{buf_size};
    if (!_interface.read(buf, actual, block) || actual == 0) {
        M5_LIB_LOGE("Failed to read %u %u", block, actual);
        goto skip;
    }

    {
        uint32_t offset{}, idx{};
        TLV tlv{};
        do {
            auto decoded = tlv.decode(buf + offset, actual > offset ? actual - offset : 0);
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

skip:
    free(buf);
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
    uint16_t buf_size = ((ab.current_ndef_message_length() + 15) >> 4) << 4;
    uint8_t* buf{};

    if (buf_size) {
        buf = static_cast<uint8_t*>(malloc(buf_size));

        if (!buf) {
            M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
            return false;
        }
        uint16_t actual = buf_size;
        if (!_interface.read(buf, actual, block + 1) || actual != buf_size) {
            M5_LIB_LOGE("Failed to read %u/%u", actual, buf_size);
            goto skip;
        }

        {
            uint16_t decoded{};
            uint16_t idx{};
            while (decoded < ab.current_ndef_message_length()) {
                Record r{};
                auto len = r.decode(buf + decoded, actual - decoded);
                if (!len) {
                    M5_LIB_LOGE("Failed to decode %u", idx);
                    goto skip;
                }
                tmp.push_back(r);
                decoded += len;
                ++idx;
            }
        }
        tlv = tmp;
    }
    ret = true;

skip:
    free(buf);
    return ret;
}

bool NDEFLayer::read_type4(std::vector<m5::nfc::ndef::TLV>& tlvs,
                           const m5::nfc::ndef::type4::FileControlTagBits fc_bits)
{
    return (_interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE) ? read_type4_desfire(tlvs, fc_bits)
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
        return false;
    }
    if (ndef_file_size && ndef_file_size < 2) {
        return false;
    }
    if (ndef_file_size && record_size > (ndef_file_size - 2)) {
        return false;
    }
    const uint32_t total_size = record_size + 2;  // NLEN + payload
    if (user_size && total_size > user_size) {
        return false;
    }

    std::vector<uint8_t> msg{};
    msg.resize(record_size);
    uint32_t offset{};
    for (auto&& r : src.records()) {
        auto len = r.encode(msg.data() + offset, record_size - offset);
        if (!len) {
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
    using type4::CapabilityContainer;
    using type4::DESFIRE_LIGHT_DF_NAME;
    using type4::DESFIRE_LIGHT_NDEF_FILE_NO;
    using type4::DESFIRE_NDEF_APP_ID;
    using type4::DESFIRE_NDEF_FILE_NO;
    using type4::FileControlTag;

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
    const bool is_light = _interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE_LIGHT;
    if (is_light) {
        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
            return false;
        }
        for (auto&& fctlv : cc.fctlvs) {
            if (!type4::contains_file_control_tag(fc_bits, fctlv.fctag())) {
                continue;
            }
            if (fctlv.fctag() == FileControlTag::Proprietary) {
                return false;
            }
            const ReadFn read_message = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
                return dfs.readData(out, DESFIRE_LIGHT_NDEF_FILE_NO, offset, len);
            };
            if (!read_type4_message(tlvs, cc, fctlv, read_message)) {
                return false;
            }
        }
        return true;
    }
    if (!dfs.selectApplication(DESFIRE_NDEF_APP_ID)) {
        return false;
    }

    for (auto&& fctlv : cc.fctlvs) {
        if (!type4::contains_file_control_tag(fc_bits, fctlv.fctag())) {
            continue;
        }
        if (fctlv.fctag() == FileControlTag::Proprietary) {
            return false;
        }
        const ReadFn read_message = [&dfs](std::vector<uint8_t>& out, const uint16_t offset, const uint16_t len) {
            return dfs.readData(out, DESFIRE_NDEF_FILE_NO, offset, len);
        };
        if (!read_type4_message(tlvs, cc, fctlv, read_message)) {
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

    TLV tmp{Tag::Message};
    bool ret{};

    uint16_t block            = _interface.first_user_block();
    const uint16_t last_block = _interface.last_user_block();
    if (block == 0xFFFF || last_block == 0xFFFF) {
        return false;
    }

    // Read CC + TLV
    const uint16_t buf_size = _interface.user_area_size();
    uint8_t* buf            = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }

    if (buf) {
        uint16_t actual = buf_size;
        if (!_interface.read(buf, actual, block) || actual != buf_size) {
            M5_LIB_LOGE("Failed to read %u %u/%u", block, actual, buf_size);
            goto skip;
        }

        {
            uint32_t offset = cc.size();
            uint32_t idx{};
            TLV tlv{};
            do {
                auto decoded = tlv.decode(buf + offset, actual > offset ? actual - offset : 0);
                // Even if decoding fails, return the results up to that point and treat it as a success
                if (!decoded) {
                    M5_LIB_LOGW("Failed to decode [%3u]:%02X", idx, tlv.tag());
                    ret = true;
                    break;
                }
                offset += decoded;
                ++idx;
                M5_LIB_LOGV("Decoded:%u %02X", decoded, tlv.tag());

                if (contains_tag(tagBits, tlv.tag())) {
                    tlvs.push_back(tlv);
                }

            } while (!tlv.isTerminatorTLV() && !tlv.isNullTLV());
            ret = true;
        }
    }

skip:
    free(buf);
    return ret;
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
    uint8_t* buf = static_cast<uint8_t*>(malloc(encoded_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", encoded_size);
        return false;
    }

    uint32_t offset{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        const auto esz = m.encode(buf + offset, encoded_size - offset);
        M5_LIB_LOGV("   [%3u] Tag:%02X %u %u", idx, m.tag(), esz, m.required());
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            goto skip;
        }
        offset += esz;
        ++idx;
    }
    if (offset > encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        goto skip;
    }

    // Write
    // M5_LIB_LOGE(">>>>ndef write %u %u", _interface.first_user_block(), encoded_size);
    ret = _interface.write(_interface.first_user_block(), buf, encoded_size);

skip:
    free(buf);
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
    uint8_t* buf = static_cast<uint8_t*>(malloc(record_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", record_size);
        return false;
    }

    uint32_t idx{};
    uint32_t encoded{};
    for (auto&& r : tlv.records()) {
        auto len = r.encode(buf + encoded, record_size - encoded);
        if (!len) {
            M5_LIB_LOGE("Failed to encode %u", idx);
            goto skip;
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
            goto skip;
        }
        // 2) Write records
        if (!_interface.write(first_block + 1, buf, record_size)) {
            goto skip;
        }
        // 3) Write AB again (Done)
        ab.write_flag(AttributeBlock::WriteFlag::Done);  // done
        ab.update_check_sum();
        if (!_interface.write(first_block, ab.block, sizeof(ab.block))) {
            goto skip;
        }
        ret = true;
    }

skip:
    free(buf);
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
    const bool is_desfire = _interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE;
    if (!readCapabilityContainer(cc) || !cc.valid()) {
        M5_LIB_LOGE("Failed to readCapabilityContainer");
        return false;
    }
    return is_desfire ? write_type4_desfire(tlvs, cc, *dep) : write_type4_iso7816(tlvs, cc, *dep);
}

bool NDEFLayer::write_type4_desfire(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                                    isodep::IsoDEP& dep)
{
    (void)cc;

    using type4::DESFIRE_DEFAULT_KEY;
    using type4::DESFIRE_LIGHT_DF_NAME;
    using type4::DESFIRE_LIGHT_NDEF_FILE_NO;

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
    const bool is_light = _interface.supportsFilesystem() & FILE_SYSTEM_DESFIRE_LIGHT;
    if (is_light) {
        if (!dfs.selectDfNameAuto(DESFIRE_LIGHT_DF_NAME, sizeof(DESFIRE_LIGHT_DF_NAME))) {
            return false;
        }
        a::mifare::desfire::Ev2Context ctx{};
        if (!dfs.authenticateEV2First(0x00, DESFIRE_DEFAULT_KEY, ctx)) {
            return false;
        }
        a::mifare::desfire::FileSettings ndef_settings{};
        if (!dfs.getFileSettingsEV2(ndef_settings, DESFIRE_LIGHT_NDEF_FILE_NO, ctx)) {
            return false;
        }
        const int ndef_key = required_key_no_from_access_rights(ndef_settings.access_rights);
        if (ndef_key == kAccessDenied ||
            (ndef_key >= 0 && !dfs.authenticateEV2First(static_cast<uint8_t>(ndef_key), DESFIRE_DEFAULT_KEY, ctx))) {
            return false;
        }
        const auto write_with_mode = [&dfs, &ctx](const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                                                  const uint32_t data_len, const uint8_t comm_mode) {
            switch (comm_mode) {
                case 0x00:
                    return dfs.writeData(file_no, offset, data, data_len);
                case 0x01:
                    return dfs.writeDataEV2Mac(file_no, offset, data, data_len, ctx);
                case 0x03:
                    return dfs.writeDataEV2Full(file_no, offset, data, data_len, ctx);
                default:
                    return false;
            }
        };
        return write_with_mode(DESFIRE_LIGHT_NDEF_FILE_NO, 0, payload.data(), static_cast<uint32_t>(payload.size()),
                               ndef_settings.comm_mode);
    }
    if (!dfs.selectApplication(type4::DESFIRE_NDEF_APP_ID)) {
        return false;
    }
    return dfs.writeData(type4::DESFIRE_NDEF_FILE_NO, 0, payload.data(), static_cast<uint32_t>(payload.size()));
}

bool NDEFLayer::write_type4_iso7816(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                                    isodep::IsoDEP& dep)
{
    using type4::NDEF_AID;

    FileSystem fs(dep);
    const bool selected_df = fs.selectDfNameAuto(NDEF_AID, sizeof(NDEF_AID));
    if (!selected_df) {
        return false;
    }

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
        if (!build_ndef_payload(*src, 0, fctlv.ndef_file_size, payload)) {
            return false;
        }
        if (!write_chunks(write_binary, payload, max_lc)) {
            return false;
        }
    }
    return true;
}

bool NDEFLayer::write_type5(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep)
{
    bool ret{};
    const uint32_t user_size = _interface.user_area_size();

    if (tlvs.empty()) {
        return false;
    }

    std::vector<TLV> tmp{};
    if (keep) {
        bool valid{};
        if (!isValidFormat(valid, NFCForumTag::Type5)) {
            return false;
        }
        if (valid) {
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

    // Read CC
    type5::CapabilityContainer cc{};
    if (!readCapabilityContainer(cc)) {
        return false;
    }

    // Calculate encoded size
    uint32_t encoded_size =
        std::accumulate(tmp.begin(), tmp.end(), 0U, [](uint32_t acc, const TLV& m) { return acc + m.required(); });

    M5_LIB_LOGD("Encoded size:%u", encoded_size);
    uint32_t buf_size = encoded_size + (encoded_size > CC4_MAX_NDEF_LENGTH ? 8 : 4);
    if (buf_size > _interface.user_area_size()) {
        M5_LIB_LOGE("Not enough area %u/%u", encoded_size, _interface.user_area_size());
        return false;
    }

    // Make CC
    if (!cc.valid()) {
        cc.block[0] = (encoded_size > CC4_MAX_NDEF_LENGTH) ? MAGIC_NO_CC8 : MAGIC_NO_CC4;
        cc.major_version(NDEF_MAJOR_VERSION);
        cc.minor_version(NDEF_MINOR_VERSION);
        cc.ndef_size(user_size);
        cc.read_access(ACCESS_FREE);
        cc.write_access(ACCESS_FREE);
        cc.addtional_feature(0);
    }

    // Encode
    uint8_t* buf = static_cast<uint8_t*>(malloc(buf_size));
    if (!buf) {
        M5_LIB_LOGE("Failed to allocate memory %u", buf_size);
        return false;
    }
    memcpy(buf, cc.block, cc.size());

    uint8_t* tlv_buf = buf + cc.size();
    uint32_t offset{};
    uint32_t idx{};
    for (auto&& m : tmp) {
        const auto esz = m.encode(tlv_buf + offset, encoded_size - offset);
        M5_LIB_LOGD("   [%3u] Tag:%02X %u %u", idx, m.tag(), esz, m.required());
        if (!esz) {
            M5_LIB_LOGE("encode failed %u %02X", idx, m.tag());
            goto skip;
        }
        offset += esz;
        ++idx;
    }
    if (offset > encoded_size) {
        M5_LIB_LOGE("Internal error %u/%u", offset, encoded_size);
        goto skip;
    }

    // Write
    ret = _interface.write(_interface.first_user_block(), buf, buf_size);

skip:
    free(buf);
    return ret;
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
