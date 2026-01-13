/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef.cpp
  @brief NDEF related
*/
#include "ndef.hpp"
#include <M5Utility.hpp>

namespace {
constexpr char uri_na[]          = "";
constexpr char uri_http_www[]    = "http://www.";
constexpr char uri_https_www[]   = "https://www.";
constexpr char uri_http[]        = "http://";
constexpr char uri_https[]       = "https://";
constexpr char uri_tel[]         = "tel:";
constexpr char uri_mailto[]      = "mailto:";
constexpr char uri_ftp_aa[]      = "ftp://anonymous:anonymous@";
constexpr char uri_ftp_ftp[]     = "ftp://ftp.";
constexpr char uri_ftps[]        = "ftps://";
constexpr char uri_sftp[]        = "sftp://";
constexpr char uri_smb[]         = "smb://";
constexpr char uri_nfs[]         = "nfs://";
constexpr char uri_ftp[]         = "ftp://";
constexpr char uri_dev[]         = "dav://";
constexpr char uri_news[]        = "news:";
constexpr char uri_telnet[]      = "telnet://";
constexpr char uri_imap[]        = "imap:";
constexpr char uri_rstp[]        = "rtsp://";
constexpr char uri_urn[]         = "urn:";
constexpr char uri_pop[]         = "pop:";
constexpr char uri_sip[]         = "sip:";
constexpr char uri_sips[]        = "sips:";
constexpr char uri_tftp[]        = "tftp:";
constexpr char uri_btspp[]       = "btspp://";
constexpr char uri_btl2cap[]     = "btl2cap://";
constexpr char uri_btgoep[]      = "btgoep://";
constexpr char uri_tcpobex[]     = "tcpobex://";
constexpr char uri_irdaobex[]    = "irdaobex://";
constexpr char uri_file[]        = "file://";
constexpr char uri_urn_epc_id[]  = "urn:epc:id:";
constexpr char uri_urn_epc_tag[] = "urn:epc:tag:";
constexpr char uri_urn_epc_pat[] = "urn:epc:pat:";
constexpr char uri_urn_epc_raw[] = "urn:epc:raw:";
constexpr char uri_urn_epc[]     = "urn:epc:";
constexpr char uri_nfc[]         = "urn:nfc: ";

constexpr const char* uri_idc_table[] = {
    uri_na,         uri_http_www,    uri_https_www,   uri_http,        uri_https,    uri_tel,
    uri_mailto,     uri_ftp_aa,      uri_ftp_ftp,     uri_ftps,        uri_sftp,     uri_smb,
    uri_nfs,        uri_ftp,         uri_dev,         uri_news,        uri_telnet,   uri_imap,
    uri_rstp,       uri_urn,         uri_pop,         uri_sip,         uri_sips,     uri_tftp,
    uri_btspp,      uri_btl2cap,     uri_btgoep,      uri_tcpobex,     uri_irdaobex, uri_file,
    uri_urn_epc_id, uri_urn_epc_tag, uri_urn_epc_pat, uri_urn_epc_raw, uri_urn_epc,  uri_nfc,
};

inline bool is_valid_file_control_tag(const m5::nfc::ndef::type4::FileControlTag t)
{
    return t == m5::nfc::ndef::type4::FileControlTag::Message || t == m5::nfc::ndef::type4::FileControlTag::Proprietary;
}

}  // namespace

namespace m5 {
namespace nfc {
namespace ndef {

const char* get_uri_idc_string(const URIProtocol protocol)
{
    auto idx = m5::stl::to_underlying(protocol);
    return uri_idc_table[idx < m5::stl::size(uri_idc_table) ? idx : 0];
}

//
namespace type3 {

bool AttributeBlock::valid() const
{
    return version() >= 0x10 && max_block_to_read() && max_block_to_write() && blocks_for_ndef_storage() &&
           write_flag() == WriteFlag::Done && (check_sum() == calculate_check_sum());
}

uint16_t AttributeBlock::calculate_check_sum() const
{
    uint16_t sum{};
    for (uint_fast8_t i = 0; i < 14; ++i) {
        sum += block[i];
    }
    return sum;
}

uint16_t AttributeBlock::update_check_sum()
{
    uint16_t sum = calculate_check_sum();
    block[14]    = sum >> 8;
    block[15]    = sum & 0xFF;
    return sum;
}
}  // namespace type3

namespace type4 {

bool CapabilityContainer::parse(const uint8_t* buf, const uint16_t len)
{
    *this = CapabilityContainer{};
    if (!buf || len < 7) {
        return false;
    }
    this->cclen           = (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
    this->mapping_version = buf[2];
    this->mle             = (static_cast<uint16_t>(buf[3]) << 8) | buf[4];
    this->mlc             = (static_cast<uint16_t>(buf[5]) << 8) | buf[6];

    uint16_t max_len = len;
    if (cclen && cclen < max_len) {
        max_len = cclen;
    }
    uint16_t offset = 7;  // TLV
    while (offset + 2 <= max_len) {
        FileControlTLV tlv{};
        tlv.tag               = buf[offset++];
        const uint8_t tlv_len = buf[offset++];
        if (offset + tlv_len > max_len) {
            break;
        }
        tlv.len = tlv_len;

        if (is_valid_file_control_tag(static_cast<FileControlTag>(tlv.tag)) && tlv_len == 6) {
            tlv.ndef_file_id   = (static_cast<uint16_t>(buf[offset]) << 8) | buf[offset + 1];
            tlv.ndef_file_size = (static_cast<uint16_t>(buf[offset + 2]) << 8) | buf[offset + 3];
            tlv.read_access    = buf[offset + 4];
            tlv.write_access   = buf[offset + 5];
            fctlvs.emplace_back(tlv);
            M5_LIB_LOGV("type4CC: fid:%04X sz:%04x ac:%02X/%02X", tlv.ndef_file_id, tlv.ndef_file_size, tlv.read_access,
                        tlv.write_access);
        }
        offset = offset + tlv_len;
    }
    return valid();
}

CapabilityContainer::FileControlTLV CapabilityContainer::fctlv(const FileControlTag fc) const
{
    for (auto&& tlv : this->fctlvs) {
        if ((FileControlTag)tlv.tag == fc) {
            return tlv;
        }
    }
    return CapabilityContainer::FileControlTLV{};
}

}  // namespace type4

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
