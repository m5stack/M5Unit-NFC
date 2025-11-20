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
}  // namespace

namespace m5 {
namespace nfc {
namespace ndef {

const char* get_uri_idc_string(const URIProtocol protocol)
{
    auto idx = m5::stl::to_underlying(protocol);
    return uri_idc_table[idx < m5::stl::size(uri_idc_table) ? idx : 0];
}

}  // namespace ndef
}  // namespace nfc
}  // namespace m5
