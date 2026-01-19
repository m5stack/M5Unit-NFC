/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file desfire_file_system.cpp
  @brief File system base using isoDEP for MIFARE DESFire
*/
#include "desfire_file_system.hpp"
#include "nfc/layer/a/nfc_layer_a.hpp"
#include "nfc/isoDEP/isoDEP.hpp"
#include "nfc/ndef/ndef.hpp"
#include "nfc/apdu/apdu.hpp"
#include <cstring>
#include <mbedtls/aes.h>
#include <esp_random.h>
#include <M5Utility.hpp>
#include <algorithm>

using namespace m5::nfc;
using namespace m5::nfc::isodep;
using namespace m5::nfc::apdu;
using namespace m5::nfc::ndef;

namespace {

constexpr uint16_t DEFAULT_RX_LEN{1024};

bool authenticate_legacy(IsoDEP& dep, const uint8_t ins, const uint8_t key_no, const uint8_t key[16])
{
    using m5::utility::crypto::TripleDES;
    using namespace m5::nfc::a::mifare::desfire;

    if (!key) {
        return false;
    }

    TripleDES::Key16 key16{};
    std::memcpy(key16.data(), key, 16);

    uint8_t auth_key_no[1] = {key_no};
    auto cmd               = make_native_wrap_command(ins, auth_key_no, 1);

    std::vector<uint8_t> rx(DEFAULT_RX_LEN);
    uint16_t rx_len = rx.size();
    if (!dep.transceiveINF(rx.data(), rx_len, cmd.data(), cmd.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth step1 %u", rx_len);
        return false;
    }
    if (!is_more(rx.data(), rx_len) || rx_len < 10) {
        M5_LIB_LOGE("Unexpected auth step1 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }

    uint8_t ek_rndB[8]{};
    std::memcpy(ek_rndB, rx.data(), 8);

    uint8_t rndB[8]{};
    {
        uint8_t iv[8]{};
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, iv};
        if (!des.decrypt(rndB, ek_rndB, sizeof(ek_rndB), key16)) {
            return false;
        }
    }

    uint8_t rndB_rot[8]{};
    uint8_t rndA[8]{};
    for (int i = 0; i < 7; ++i) {
        rndB_rot[i] = rndB[i + 1];
    }
    rndB_rot[7] = rndB[0];
    for (auto& r : rndA) {
        r = static_cast<uint8_t>(esp_random());
    }

    uint8_t plain_AB[16]{};
    std::memcpy(plain_AB, rndA, 8);
    std::memcpy(plain_AB + 8, rndB_rot, 8);

    uint8_t ek_AB[16]{};
    {
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, ek_rndB};
        if (!des.encrypt(ek_AB, plain_AB, sizeof(plain_AB), key16)) {
            return false;
        }
    }

    auto cmd2 = make_native_wrap_command(0xAF, ek_AB, sizeof(ek_AB));
    rx_len    = rx.size();
    if (!dep.transceiveINF(rx.data(), rx_len, cmd2.data(), cmd2.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth step2 %u", rx_len);
        return false;
    }
    if (!is_successful(rx.data(), rx_len) || rx_len < 10) {
        M5_LIB_LOGE("Unexpected auth step2 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }

    uint8_t rndA_rot_from_card[8]{};
    {
        TripleDES des{TripleDES::Mode::CBC, TripleDES::Padding::None, ek_AB + 8};
        if (!des.decrypt(rndA_rot_from_card, rx.data(), 8, key16)) {
            return false;
        }
    }

    uint8_t rndA_rot[8]{};
    for (int i = 0; i < 7; ++i) {
        rndA_rot[i] = rndA[i + 1];
    }
    rndA_rot[7] = rndA[0];
    return std::memcmp(rndA_rot, rndA_rot_from_card, 8) == 0;
}

/*
void rotate_byte_left(uint8_t out[8], const uint8_t in[8])
{
    for (int i = 0; i < 7; ++i) {
        out[i] = in[i + 1];
    }
    out[7] = in[0];
}
*/

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

void aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&aes);
}

void aes_cbc_crypt(const uint8_t key[16], const uint8_t iv_in[16], const uint8_t* in, uint8_t* out, const size_t len,
                   const bool encrypt)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (encrypt) {
        mbedtls_aes_setkey_enc(&aes, key, 128);
    } else {
        mbedtls_aes_setkey_dec(&aes, key, 128);
    }
    uint8_t iv[16]{};
    std::memcpy(iv, iv_in, sizeof(iv));
    mbedtls_aes_crypt_cbc(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv, in, out);
    mbedtls_aes_free(&aes);
}

void left_shift_128(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t next = static_cast<uint8_t>(in[i] << 1);
        out[i]       = static_cast<uint8_t>(next | carry);
        carry        = (in[i] & 0x80) ? 0x01 : 0x00;
    }
}

void cmac_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    static constexpr uint8_t kRb = 0x87;
    uint8_t l[16]{};
    uint8_t zero[16]{};
    aes_ecb_encrypt(key, zero, l);
    left_shift_128(l, k1);
    if (l[0] & 0x80) {
        k1[15] ^= kRb;
    }
    left_shift_128(k1, k2);
    if (k1[0] & 0x80) {
        k2[15] ^= kRb;
    }
}

void cmac_aes_128(const uint8_t key[16], const uint8_t* msg, const size_t msg_len, uint8_t out[16])
{
    uint8_t k1[16]{};
    uint8_t k2[16]{};
    cmac_subkeys(key, k1, k2);

    const size_t n           = (msg_len + 15) / 16;
    const bool last_complete = (msg_len != 0) && (msg_len % 16 == 0);

    uint8_t last_block[16]{};
    if (n == 0) {
        last_block[0] = 0x80;
        for (int i = 0; i < 16; ++i) {
            last_block[i] ^= k2[i];
        }
    } else {
        const uint8_t* last = msg + (n - 1) * 16;
        if (last_complete) {
            std::memcpy(last_block, last, 16);
            for (int i = 0; i < 16; ++i) {
                last_block[i] ^= k1[i];
            }
        } else {
            const size_t rem = msg_len - (n - 1) * 16;
            std::memcpy(last_block, last, rem);
            last_block[rem] = 0x80;
            for (int i = 0; i < 16; ++i) {
                last_block[i] ^= k2[i];
            }
        }
    }

    uint8_t x[16]{};
    uint8_t y[16]{};
    for (size_t i = 0; i + 1 < n; ++i) {
        for (int j = 0; j < 16; ++j) {
            y[j] = static_cast<uint8_t>(x[j] ^ msg[i * 16 + j]);
        }
        aes_ecb_encrypt(key, y, x);
    }
    for (int j = 0; j < 16; ++j) {
        y[j] = static_cast<uint8_t>(x[j] ^ last_block[j]);
    }
    aes_ecb_encrypt(key, y, out);
}

void truncate_mac_even_bytes(const uint8_t in[16], uint8_t out[8])
{
    for (int i = 0; i < 8; ++i) {
        out[i] = in[i * 2 + 1];
    }
}

std::vector<uint8_t> pad_iso9797_m2(const uint8_t* data, const size_t len)
{
    std::vector<uint8_t> out;
    const size_t pad_len = 16 - (len % 16);
    const size_t total   = len + pad_len;
    out.resize(total);
    if (len) {
        std::memcpy(out.data(), data, len);
    }
    out[len] = 0x80;
    return out;
}

bool unpad_iso9797_m2(std::vector<uint8_t>& data)
{
    if (data.empty() || (data.size() % 16) != 0) {
        return false;
    }
    size_t i = data.size();
    while (i > 0 && data[i - 1] == 0x00) {
        --i;
    }
    if (i == 0 || data[i - 1] != 0x80) {
        return false;
    }
    data.resize(i - 1);
    return true;
}

void build_sv(const uint8_t label0, const uint8_t label1, const uint8_t rndA[16], const uint8_t rndB[16],
              uint8_t out[32])
{
    out[0] = label0;
    out[1] = label1;
    out[2] = 0x00;
    out[3] = 0x01;
    out[4] = 0x00;
    out[5] = 0x80;
    std::memcpy(out + 6, rndA, 8);
    for (int i = 0; i < 6; ++i) {
        out[8 + i] ^= rndB[i];
    }
    std::memcpy(out + 14, rndB + 6, 10);
    std::memcpy(out + 24, rndA + 8, 8);
}

void build_sm_iv(const uint8_t label0, const uint8_t label1, const uint8_t ti[4], const uint16_t cmd_ctr,
                 const uint8_t key[16], uint8_t out[16])
{
    uint8_t plain[16]{};
    plain[0] = label0;
    plain[1] = label1;
    std::memcpy(plain + 2, ti, 4);
    plain[6] = static_cast<uint8_t>(cmd_ctr & 0xFF);
    plain[7] = static_cast<uint8_t>((cmd_ctr >> 8) & 0xFF);
    aes_ecb_encrypt(key, plain, out);
}

bool transceive_sm_full(m5::nfc::isodep::IsoDEP& iso_dep, const uint8_t cmd, const uint8_t* cmd_header,
                        const size_t cmd_header_len, const uint8_t* cmd_data, const size_t cmd_data_len,
                        m5::nfc::a::mifare::desfire::Ev2Context& ctx, std::vector<uint8_t>* resp_plain)
{
    const uint16_t cmd_ctr = ctx.cmd_ctr;

    std::vector<uint8_t> enc_data;
    if (cmd_data_len) {
        enc_data = pad_iso9797_m2(cmd_data, cmd_data_len);
        uint8_t iv[16]{};
        build_sm_iv(0xA5, 0x5A, ctx.ti, cmd_ctr, ctx.ses_enc_key, iv);
        std::vector<uint8_t> tmp(enc_data.size());
        aes_cbc_crypt(ctx.ses_enc_key, iv, enc_data.data(), tmp.data(), enc_data.size(), true);
        enc_data.swap(tmp);
    }

    std::vector<uint8_t> mac_input;
    mac_input.reserve(1 + 2 + 4 + cmd_header_len + enc_data.size());
    mac_input.push_back(cmd);
    mac_input.push_back(static_cast<uint8_t>(cmd_ctr & 0xFF));
    mac_input.push_back(static_cast<uint8_t>((cmd_ctr >> 8) & 0xFF));
    mac_input.insert(mac_input.end(), ctx.ti, ctx.ti + sizeof(ctx.ti));
    if (cmd_header_len) {
        mac_input.insert(mac_input.end(), cmd_header, cmd_header + cmd_header_len);
    }
    if (!enc_data.empty()) {
        mac_input.insert(mac_input.end(), enc_data.begin(), enc_data.end());
    }

    uint8_t mac_full[16]{};
    uint8_t mac_trunc[8]{};
    cmac_aes_128(ctx.ses_mac_key, mac_input.data(), mac_input.size(), mac_full);
    truncate_mac_even_bytes(mac_full, mac_trunc);

    std::vector<uint8_t> cmd_data_sm;
    cmd_data_sm.reserve(cmd_header_len + enc_data.size() + sizeof(mac_trunc));
    if (cmd_header_len) {
        cmd_data_sm.insert(cmd_data_sm.end(), cmd_header, cmd_header + cmd_header_len);
    }
    if (!enc_data.empty()) {
        cmd_data_sm.insert(cmd_data_sm.end(), enc_data.begin(), enc_data.end());
    }
    cmd_data_sm.insert(cmd_data_sm.end(), mac_trunc, mac_trunc + sizeof(mac_trunc));

    auto apdu = m5::nfc::a::mifare::desfire::make_native_wrap_command(cmd, cmd_data_sm.data(),
                                                                      static_cast<uint16_t>(cmd_data_sm.size()));
    /*
    M5_LIB_LOGE("SM tx cmd:%02X hdr:%u data:%u mac:%u", cmd, static_cast<unsigned>(cmd_header_len),
                static_cast<unsigned>(enc_data.size()), static_cast<unsigned>(sizeof(mac_trunc)));
    m5::utility::log::dump(apdu.data(), apdu.size(), false);
    M5_LIB_LOGE("SM tx MAC input");
    m5::utility::log::dump(mac_input.data(), mac_input.size(), false);
    */

    std::vector<uint8_t> rx(DEFAULT_RX_LEN);
    uint16_t rx_len = rx.size();
    if (!iso_dep.transceiveINF(rx.data(), rx_len, apdu.data(), apdu.size(), nullptr) || rx_len < 2) {
        return false;
    }

    if (rx_len == 2) {
        M5_LIB_LOGE("SM response status %02X", rx[1]);
        return false;
    }
    if (rx_len < 10) {
        M5_LIB_LOGE("SM response length %u", rx_len);
        return false;
    }

    const uint8_t rc            = rx[rx_len - 1];
    const uint16_t cmd_ctr_resp = static_cast<uint16_t>(cmd_ctr + 1);
    const size_t data_len       = rx_len - 2;
    if (data_len < 8) {
        return false;
    }
    const size_t enc_resp_len = data_len - 8;
    const uint8_t* enc_resp   = rx.data();
    const uint8_t* mac_resp   = rx.data() + enc_resp_len;

    std::vector<uint8_t> mac_resp_input;
    mac_resp_input.reserve(1 + 2 + 4 + enc_resp_len);
    mac_resp_input.push_back(rc);
    mac_resp_input.push_back(static_cast<uint8_t>(cmd_ctr_resp & 0xFF));
    mac_resp_input.push_back(static_cast<uint8_t>((cmd_ctr_resp >> 8) & 0xFF));
    mac_resp_input.insert(mac_resp_input.end(), ctx.ti, ctx.ti + sizeof(ctx.ti));
    if (enc_resp_len) {
        mac_resp_input.insert(mac_resp_input.end(), enc_resp, enc_resp + enc_resp_len);
    }

    uint8_t mac_resp_full[16]{};
    uint8_t mac_resp_trunc[8]{};
    cmac_aes_128(ctx.ses_mac_key, mac_resp_input.data(), mac_resp_input.size(), mac_resp_full);
    truncate_mac_even_bytes(mac_resp_full, mac_resp_trunc);
    if (std::memcmp(mac_resp_trunc, mac_resp, sizeof(mac_resp_trunc)) != 0) {
        M5_LIB_LOGE("SM rx MAC input");
        m5::utility::log::dump(mac_resp_input.data(), mac_resp_input.size(), false);
        M5_LIB_LOGE("SM MAC mismatch");
        return false;
    }

    ctx.cmd_ctr = cmd_ctr_resp;
    if (rc != 0x00) {
        M5_LIB_LOGE("SM RC %02X", rc);
        return false;
    }

    if (resp_plain) {
        resp_plain->clear();
        if (enc_resp_len) {
            std::vector<uint8_t> dec(enc_resp_len);
            uint8_t iv[16]{};
            build_sm_iv(0x5A, 0xA5, ctx.ti, cmd_ctr_resp, ctx.ses_enc_key, iv);
            aes_cbc_crypt(ctx.ses_enc_key, iv, enc_resp, dec.data(), enc_resp_len, false);
            if (!unpad_iso9797_m2(dec)) {
                return false;
            }
            resp_plain->swap(dec);
        }
    }
    return true;
}

bool transceive_sm_mac(m5::nfc::isodep::IsoDEP& iso_dep, const uint8_t cmd, const uint8_t* cmd_header,
                       const size_t cmd_header_len, const uint8_t* cmd_data, const size_t cmd_data_len,
                       m5::nfc::a::mifare::desfire::Ev2Context& ctx, std::vector<uint8_t>* resp_plain)
{
    const uint16_t cmd_ctr = ctx.cmd_ctr;

    std::vector<uint8_t> mac_input;
    mac_input.reserve(1 + 2 + 4 + cmd_header_len + cmd_data_len);
    mac_input.push_back(cmd);
    mac_input.push_back(static_cast<uint8_t>(cmd_ctr & 0xFF));
    mac_input.push_back(static_cast<uint8_t>((cmd_ctr >> 8) & 0xFF));
    mac_input.insert(mac_input.end(), ctx.ti, ctx.ti + sizeof(ctx.ti));
    if (cmd_header_len) {
        mac_input.insert(mac_input.end(), cmd_header, cmd_header + cmd_header_len);
    }
    if (cmd_data_len) {
        mac_input.insert(mac_input.end(), cmd_data, cmd_data + cmd_data_len);
    }

    uint8_t mac_full[16]{};
    uint8_t mac_trunc[8]{};
    cmac_aes_128(ctx.ses_mac_key, mac_input.data(), mac_input.size(), mac_full);
    truncate_mac_even_bytes(mac_full, mac_trunc);

    std::vector<uint8_t> cmd_data_sm;
    cmd_data_sm.reserve(cmd_header_len + cmd_data_len + sizeof(mac_trunc));
    if (cmd_header_len) {
        cmd_data_sm.insert(cmd_data_sm.end(), cmd_header, cmd_header + cmd_header_len);
    }
    if (cmd_data_len) {
        cmd_data_sm.insert(cmd_data_sm.end(), cmd_data, cmd_data + cmd_data_len);
    }
    cmd_data_sm.insert(cmd_data_sm.end(), mac_trunc, mac_trunc + sizeof(mac_trunc));

    auto apdu = m5::nfc::a::mifare::desfire::make_native_wrap_command(cmd, cmd_data_sm.data(),
                                                                      static_cast<uint16_t>(cmd_data_sm.size()));
    std::vector<uint8_t> rx(DEFAULT_RX_LEN);
    uint16_t rx_len = rx.size();
    if (!iso_dep.transceiveINF(rx.data(), rx_len, apdu.data(), apdu.size(), nullptr) || rx_len < 2) {
        return false;
    }
    if (rx_len == 2) {
        M5_LIB_LOGE("SM response status %02X", rx[1]);
        return false;
    }
    if (rx_len < 10) {
        M5_LIB_LOGE("SM response length %u", rx_len);
        return false;
    }

    const uint8_t rc            = rx[rx_len - 1];
    const uint16_t cmd_ctr_resp = static_cast<uint16_t>(cmd_ctr + 1);
    const size_t data_len       = rx_len - 2;
    if (data_len < 8) {
        return false;
    }
    const size_t resp_data_len = data_len - 8;
    const uint8_t* resp_data   = rx.data();
    const uint8_t* mac_resp    = rx.data() + resp_data_len;

    std::vector<uint8_t> mac_resp_input;
    mac_resp_input.reserve(1 + 2 + 4 + resp_data_len);
    mac_resp_input.push_back(rc);
    mac_resp_input.push_back(static_cast<uint8_t>(cmd_ctr_resp & 0xFF));
    mac_resp_input.push_back(static_cast<uint8_t>((cmd_ctr_resp >> 8) & 0xFF));
    mac_resp_input.insert(mac_resp_input.end(), ctx.ti, ctx.ti + sizeof(ctx.ti));
    if (resp_data_len) {
        mac_resp_input.insert(mac_resp_input.end(), resp_data, resp_data + resp_data_len);
    }

    uint8_t mac_resp_full[16]{};
    uint8_t mac_resp_trunc[8]{};
    cmac_aes_128(ctx.ses_mac_key, mac_resp_input.data(), mac_resp_input.size(), mac_resp_full);
    truncate_mac_even_bytes(mac_resp_full, mac_resp_trunc);
    if (std::memcmp(mac_resp_trunc, mac_resp, sizeof(mac_resp_trunc)) != 0) {
        M5_LIB_LOGE("SM MAC mismatch");
        return false;
    }

    ctx.cmd_ctr = cmd_ctr_resp;
    if (rc != 0x00) {
        M5_LIB_LOGE("SM RC %02X", rc);
        return false;
    }

    if (resp_plain) {
        resp_plain->assign(resp_data, resp_data + resp_data_len);
    }
    return true;
}

bool build_cc(std::vector<uint8_t>& out, uint16_t& ndef_fid, uint16_t& ndef_size,
              const m5::nfc::a::mifare::desfire::NdefFormatOptions& opt)
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

}  // namespace

namespace m5 {
namespace nfc {
namespace a {
namespace mifare {
namespace desfire {

std::vector<uint8_t> make_native_wrap_command(const uint8_t ins, const uint8_t* data, const uint16_t data_len)
{
    // Le(0) are always assigned
    const uint8_t lc_len = (data_len == 0) ? 0 : ((data_len > 255) ? 3 : 1);

    std::vector<uint8_t> cmd{};
    cmd.resize(4 + lc_len + data_len + 1);

    uint32_t offset{};

    // ---- Header
    cmd[offset++] = 0x90;
    cmd[offset++] = ins;
    cmd[offset++] = 0x00;
    cmd[offset++] = 0x00;

    // ---- Body
    // Lc
    if (lc_len == 3) {
        cmd[offset++] = 0x00;
        cmd[offset++] = static_cast<uint8_t>((data_len >> 8) & 0xFF);
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    } else if (lc_len == 1) {
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    }
    // Data
    if (data_len) {
        std::memcpy(cmd.data() + offset, data, data_len);
        offset += data_len;
    }
    cmd[offset++] = 0x00;
    return cmd;
}

DESFireFileSystem::DESFireFileSystem(m5::nfc::NFCLayerA& layer)
    : FileSystem{*layer.isoDEP() /* always exists _isoDEP */}
{
}

m5::stl::expected<void, uint8_t> DESFireFileSystem::createApplication(const uint8_t aid[3], const uint8_t key_settings1,
                                                                      const uint8_t key_settings2,
                                                                      const uint16_t iso_fid, const uint8_t* df_name,
                                                                      const uint8_t df_name_len)
{
    std::vector<uint8_t> data;
    data.reserve(5 + 2 + df_name_len);
    data.push_back(aid[0]);
    data.push_back(aid[1]);
    data.push_back(aid[2]);
    data.push_back(key_settings1);
    data.push_back(key_settings2);

    if (iso_fid || (df_name && df_name_len)) {
        data.push_back(static_cast<uint8_t>(iso_fid & 0xFF));
        data.push_back(static_cast<uint8_t>((iso_fid >> 8) & 0xFF));
    }
    if (df_name && df_name_len) {
        data.insert(data.end(), df_name, df_name + df_name_len);
    }

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_CREATE_APPLICATION), data.data(), data.size());

    //M5_LIB_LOGE("cmd:");
    //m5::utility::log::dump(cmd.data(), cmd.size(), false);

    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return m5::stl::unexpected<uint8_t>{0xFF};
    }
    const uint8_t status = status_code(rx, rx_len);
    if (is_successful(rx, rx_len)) {
        return {};
    }
    M5_LIB_LOGE("CreateApplication failed (%02X)", status);
    return m5::stl::unexpected<uint8_t>{status};
}

bool DESFireFileSystem::deleteApplication(const uint8_t aid[3])
{
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_DELETE_APPLICATION), aid, 3);
    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (is_successful(rx, rx_len)) {
        return true;
    }
    M5_LIB_LOGE("DeleteApplication failed (%02X)", status_code(rx, rx_len));
    return false;
}

bool DESFireFileSystem::createStdDataFile(const uint8_t file_no, const uint16_t iso_fid, const uint8_t comm_mode,
                                          const uint16_t access_rights, const uint32_t file_size)
{
    uint8_t data[1 + 2 + 1 + 2 + 3]{};
    uint8_t* p = data;

    *p++ = file_no;
    *p++ = static_cast<uint8_t>(iso_fid & 0xFF);
    *p++ = static_cast<uint8_t>((iso_fid >> 8) & 0xFF);
    *p++ = comm_mode;
    *p++ = static_cast<uint8_t>((access_rights >> 8) & 0xFF);
    *p++ = static_cast<uint8_t>(access_rights & 0xFF);
    pack_le24(p, file_size);
    p += 3;

    const uint16_t len = static_cast<uint16_t>(p - data);
    auto cmd           = make_native_wrap_command(m5::stl::to_underlying(INS::DF_CREATE_STD_DATA_FILE), data, len);

    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (is_successful(rx, rx_len)) {
        return true;
    }
    M5_LIB_LOGE("CreateStdDataFile failed (%02X)", status_code(rx, rx_len));
    return false;
}

bool DESFireFileSystem::readData(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                                 const uint32_t length)
{
    out.clear();

    uint8_t data[1 + 3 + 3]{};
    uint8_t* p = data;
    *p++       = file_no;
    pack_le24(p, offset);
    p += 3;
    pack_le24(p, length);
    p += 3;

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_READ_DATA), data, sizeof(data));

    const size_t rx_cap = length ? static_cast<size_t>(length + 2) : static_cast<size_t>(DEFAULT_RX_LEN);
    std::vector<uint8_t> rx(rx_cap);
    uint16_t rx_len = static_cast<uint16_t>(rx.size());
    if (!transceive(rx.data(), rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (!is_successful(rx.data(), rx_len)) {
        return false;
    }
    out.assign(rx.begin(), rx.begin() + (rx_len - 2));
    return true;
}

bool DESFireFileSystem::readDataLight(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                                      const uint32_t length)
{
    out.clear();

    uint8_t data[1 + 3 + 3]{};
    uint8_t* p = data;
    *p++       = file_no;
    pack_le24(p, offset);
    p += 3;
    pack_le24(p, length);
    p += 3;

    auto cmd = make_apdu_command(DESFIRE_APDU_CLA, DESFIRE_LIGHT_INS_READ_DATA, 0x00, 0x00, data, sizeof(data), 256);

    const size_t rx_cap = length ? static_cast<size_t>(length + 2) : static_cast<size_t>(DEFAULT_RX_LEN);
    std::vector<uint8_t> rx(rx_cap);
    uint16_t rx_len = static_cast<uint16_t>(rx.size());
    if (!transceive(rx.data(), rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (!is_successful(rx.data(), rx_len)) {
        return false;
    }
    out.assign(rx.begin(), rx.begin() + (rx_len - 2));
    return true;
}

bool DESFireFileSystem::readDataLightEV2Full(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                                             const uint32_t length, Ev2Context& ctx)
{
    out.clear();

    // ReadData: CmdHeader = FileNo + Offset + Length, CmdData = none
    uint8_t header[1 + 3 + 3]{};
    header[0] = file_no;
    pack_le24(header + 1, offset);
    pack_le24(header + 4, length);

    std::vector<uint8_t> resp;
    if (!transceive_sm_full(_isoDEP, DESFIRE_LIGHT_INS_READ_DATA, header, sizeof(header), nullptr, 0, ctx, &resp)) {
        return false;
    }
    out = std::move(resp);
    return true;
}

bool DESFireFileSystem::readDataLightEV2(std::vector<uint8_t>& out, const uint8_t file_no, const uint32_t offset,
                                         const uint32_t length, Ev2Context& ctx)
{
    out.clear();

    // ReadData: CmdHeader = FileNo + Offset + Length, CmdData = none
    uint8_t header[1 + 3 + 3]{};
    header[0] = file_no;
    pack_le24(header + 1, offset);
    pack_le24(header + 4, length);

    std::vector<uint8_t> resp;
    if (!transceive_sm_mac(_isoDEP, DESFIRE_LIGHT_INS_READ_DATA, header, sizeof(header), nullptr, 0, ctx, &resp)) {
        return false;
    }
    out = std::move(resp);
    return true;
}

bool DESFireFileSystem::writeData(const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                                  const uint32_t data_len)
{
    if (!data || data_len == 0) {
        return false;
    }

    constexpr uint32_t kParamLen = 1 + 3 + 3;
    constexpr uint32_t kMaxLc    = 255;
    const auto cfg               = _isoDEP.config();
    const uint16_t overhead      = 1 + (cfg.use_cid ? 1U : 0U) + (cfg.use_nad ? 1U : 0U);
    const uint16_t tx_frame_cap  = (cfg.pcd_max_frame_tx > (overhead + 2)) ? (cfg.pcd_max_frame_tx - overhead - 2) : 0;
    const uint16_t max_inf_frame = (tx_frame_cap < cfg.fsc) ? tx_frame_cap : cfg.fsc;
    const uint16_t safe_inf      = (max_inf_frame > 1) ? static_cast<uint16_t>(max_inf_frame - 1) : 0;  // margin
    constexpr uint32_t kApduBase = 4 + 1 + 1 + kParamLen;
    const uint32_t max_cmd_chunk = (safe_inf > kApduBase) ? (safe_inf - kApduBase) : 0;
    const uint32_t kMaxChunk     = std::min<uint32_t>(kMaxLc - kParamLen, max_cmd_chunk);

    // M5_LIB_LOGE("max inf %u kMaxChunk %u", max_inf_frame, kMaxChunk);

    uint32_t written{};
    while (written < data_len) {
        const uint32_t chunk = std::min<uint32_t>(data_len - written, kMaxChunk);
        std::vector<uint8_t> payload;
        payload.resize(kParamLen + chunk);
        uint8_t* p = payload.data();
        *p++       = file_no;
        pack_le24(p, offset + written);
        p += 3;
        pack_le24(p, chunk);
        p += 3;
        std::memcpy(p, data + written, chunk);

        auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_WRITE_DATA), payload.data(),
                                            static_cast<uint16_t>(payload.size()));

        uint8_t rx[16]{};
        uint16_t rx_len = sizeof(rx);
        if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
            M5_LIB_LOGE("Transceive failed %u", written);
            return false;
        }
        if (!is_successful(rx, rx_len)) {
            M5_LIB_LOGE("WriteData failed %u (%02X)", written, status_code(rx, rx_len));
            return false;
        }
        written += chunk;
    }
    return true;
}

bool DESFireFileSystem::writeDataLight(const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                                       const uint32_t data_len)
{
    if (!data || data_len == 0) {
        return false;
    }

    constexpr uint32_t kParamLen = 1 + 3 + 3;
    constexpr uint32_t kMaxLc    = 255;
    const auto cfg               = _isoDEP.config();
    const uint16_t overhead      = 1 + (cfg.use_cid ? 1U : 0U) + (cfg.use_nad ? 1U : 0U);
    const uint16_t tx_frame_cap  = (cfg.pcd_max_frame_tx > (overhead + 2)) ? (cfg.pcd_max_frame_tx - overhead - 2) : 0;
    const uint16_t max_inf_frame = (tx_frame_cap < cfg.fsc) ? tx_frame_cap : cfg.fsc;
    const uint16_t safe_inf      = (max_inf_frame > 1) ? static_cast<uint16_t>(max_inf_frame - 1) : 0;  // margin
    constexpr uint32_t kApduBase = 4 + 1 + 1 + kParamLen;
    const uint32_t max_cmd_chunk = (safe_inf > kApduBase) ? (safe_inf - kApduBase) : 0;
    const uint32_t kMaxChunk     = std::min<uint32_t>(kMaxLc - kParamLen, max_cmd_chunk);

    uint32_t written{};
    while (written < data_len) {
        const uint32_t chunk = std::min<uint32_t>(data_len - written, kMaxChunk);
        std::vector<uint8_t> payload;
        payload.resize(kParamLen + chunk);
        uint8_t* p = payload.data();
        *p++       = file_no;
        pack_le24(p, offset + written);
        p += 3;
        pack_le24(p, chunk);
        p += 3;
        std::memcpy(p, data + written, chunk);

        auto cmd = make_apdu_command(DESFIRE_APDU_CLA, DESFIRE_LIGHT_INS_WRITE_DATA, 0x00, 0x00, payload.data(),
                                     static_cast<uint16_t>(payload.size()), 256);

        uint8_t rx[16]{};
        uint16_t rx_len = sizeof(rx);
        if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
            M5_LIB_LOGE("Transceive failed %u", written);
            return false;
        }
        if (!is_successful(rx, rx_len)) {
            M5_LIB_LOGE("WriteDataLight failed %u (%02X)", written, status_code(rx, rx_len));
            return false;
        }
        written += chunk;
    }
    return true;
}

bool DESFireFileSystem::writeDataLightEV2(const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                                          const uint32_t data_len, Ev2Context& ctx)
{
    if (!data || data_len == 0) {
        return false;
    }

    constexpr uint32_t kCmdHeaderLen = 1 + 3 + 3;
    constexpr uint32_t kMacLen       = 8;
    constexpr uint32_t kMaxLc        = 255;
    const uint32_t max_chunk         = (kMaxLc > (kCmdHeaderLen + kMacLen)) ? (kMaxLc - kCmdHeaderLen - kMacLen) : 0;
    if (!max_chunk) {
        return false;
    }

    uint32_t written{};
    while (written < data_len) {
        const uint32_t chunk = std::min<uint32_t>(data_len - written, max_chunk);
        uint8_t cmd_header[kCmdHeaderLen]{};
        uint8_t* p = cmd_header;
        *p++       = file_no;
        pack_le24(p, offset + written);
        p += 3;
        pack_le24(p, chunk);

        if (!transceive_sm_mac(_isoDEP, m5::stl::to_underlying(INS::DF_WRITE_DATA), cmd_header, sizeof(cmd_header),
                               data + written, chunk, ctx, nullptr)) {
            return false;
        }
        written += chunk;
    }
    return true;
}

bool DESFireFileSystem::writeDataLightEV2Full(const uint8_t file_no, const uint32_t offset, const uint8_t* data,
                                              const uint32_t data_len, Ev2Context& ctx)
{
    if (!data || data_len == 0) {
        return false;
    }

    constexpr uint32_t kCmdHeaderLen = 1 + 3 + 3;
    constexpr uint32_t kMacLen       = 8;
    constexpr uint32_t kMaxLc        = 255;
    const uint32_t max_enc_len       = (kMaxLc > (kCmdHeaderLen + kMacLen)) ? (kMaxLc - kCmdHeaderLen - kMacLen) : 0;
    if (max_enc_len < 16) {
        return false;
    }
    const uint32_t max_plain_blocks = (max_enc_len / 16) - 1;  // padding always adds 1 block
    const uint32_t max_chunk =
        max_plain_blocks ? (max_plain_blocks * 16U + 15U) : 0;  // max plain bytes fitting padded length
    if (!max_chunk) {
        return false;
    }

    uint32_t written{};
    while (written < data_len) {
        const uint32_t chunk = std::min<uint32_t>(data_len - written, max_chunk);
        uint8_t cmd_header[kCmdHeaderLen]{};
        uint8_t* p = cmd_header;
        *p++       = file_no;
        pack_le24(p, offset + written);
        p += 3;
        pack_le24(p, chunk);

        if (!transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_WRITE_DATA), cmd_header, sizeof(cmd_header),
                                data + written, chunk, ctx, nullptr)) {
            return false;
        }
        written += chunk;
    }
    return true;
}

bool DESFireFileSystem::selectApplication(const uint8_t aid[3])
{
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_SELECT_APPLICATION), aid, 3);
    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);

    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to selectApplication %u", rx_len);
        return false;
    }
    if (!is_successful(rx, rx_len)) {
        M5_LIB_LOGE("selectApplication failed (%02X)", status_code(rx, rx_len));
        return false;
    }
    return true;
}

bool DESFireFileSystem::selectApplication(const uint32_t aid24)
{
    uint8_t aid[3]{};
    aid[0] = aid24 >> 16;
    aid[1] = aid24 >> 8;
    aid[2] = aid24 & 0xFF;
    return selectApplication(aid);
}

bool DESFireFileSystem::getApplicationIDs(std::vector<desfire_aid_t>& out)
{
    out.clear();
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_APPLICATION_IDS));

    uint8_t rx[512]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to getApplicationIDs %u", rx_len);
        return false;
    }
    if (is_successful(rx, rx_len)) {
        const uint16_t data_len = rx_len - 2;
        if (data_len % 3 != 0) {
            M5_LIB_LOGW("getApplicationIDs: secured response not supported");
            return false;
        }

        const uint16_t n = data_len / 3;
        out.reserve(n);
        for (uint_fast16_t i = 0; i < n; ++i) {
            desfire_aid_t aid{};
            aid.aid[0] = rx[i * 3 + 0];
            aid.aid[1] = rx[i * 3 + 1];
            aid.aid[2] = rx[i * 3 + 2];
            out.emplace_back(aid);
        }
        return true;
    }
    return false;
}

bool DESFireFileSystem::getFreeMemory(uint32_t& out)
{
    out      = 0;
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_FREE_MEMORY));

    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("transceive failed, rx_len=%u", rx_len);
        return false;
    }

    if (!is_successful(rx, rx_len)) {
        M5_LIB_LOGE("not successful, status=%02X", status_code(rx, rx_len));
        return false;
    }

    const uint16_t data_len = static_cast<uint16_t>(rx_len - 2);
    if (data_len > 3) {
        M5_LIB_LOGE("Secured response not supported");
        return false;
    }
    if (data_len == 2) {
        out = static_cast<uint32_t>(rx[0]) | (static_cast<uint32_t>(rx[1]) << 8);
        return true;
    }
    if (data_len == 3) {
        out = unpack_le24(rx);
        return true;
    }
    M5_LIB_LOGE("unexpected data_len=%u", data_len);
    return false;
}

bool DESFireFileSystem::getKeySettings(uint8_t& key_settings, uint8_t& key_count)
{
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_KEY_SETTINGS));

    uint8_t rx[8]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 4) {
        return false;
    }
    if (!is_successful(rx, rx_len)) {
        return false;
    }
    const uint16_t data_len = static_cast<uint16_t>(rx_len - 2);
    if (data_len > 2) {
        M5_LIB_LOGW("Secured response not supported");
        return false;
    }
    key_settings = rx[0];
    key_count    = rx[1];
    return true;
}

bool DESFireFileSystem::formatPICC(const uint8_t* picc_master_key, const AuthMode mode)
{
    if (!picc_master_key) {
        return false;
    }

    if (!selectApplication()) {
        M5_LIB_LOGE("Failed to select app");
        return false;
    }

    bool ok = false;
    if (mode == AuthMode::DES || mode == AuthMode::Auto) {
        ok = authenticateDES(0x00, picc_master_key);
        if (!ok) {
            ok = authenticateISO(0x00, picc_master_key);
        }
    }
    if (!ok && (mode == AuthMode::AES || mode == AuthMode::Auto)) {
        ok = authenticateAES(0x00, picc_master_key);
    }
    if (!ok) {
        M5_LIB_LOGE("Failed to auth");
        return false;
    }

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_FORMAT_PICC));
    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    return is_successful(rx, rx_len);
}

bool DESFireFileSystem::setConfigurationFileRenaming(const FileRename& first, const FileRename* second)
{
    std::vector<uint8_t> data{};
    data.push_back(0x08);     // File renaming option
    uint8_t file_opt = 0x01;  // Update ISO File ID
    if (second) {
        file_opt |= 0x02;  // Update two files
    }
    data.push_back(file_opt);
    data.push_back(first.old_file_no);
    data.push_back(first.new_file_no);
    data.push_back(static_cast<uint8_t>(first.new_file_id & 0xFF));
    data.push_back(static_cast<uint8_t>((first.new_file_id >> 8) & 0xFF));
    if (second) {
        data.push_back(second->old_file_no);
        data.push_back(second->new_file_no);
        data.push_back(static_cast<uint8_t>(second->new_file_id & 0xFF));
        data.push_back(static_cast<uint8_t>((second->new_file_id >> 8) & 0xFF));
    }

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_SET_CONFIGURATION), data.data(), data.size());
    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("failed");
        M5_DUMPE(rx, rx_len);
        return false;
    }
    return is_successful(rx, rx_len);
}

bool DESFireFileSystem::setConfigurationFileRenamingEV2Full(const FileRename& first, const FileRename* second,
                                                            Ev2Context& ctx)
{
    std::vector<uint8_t> data{};
    uint8_t file_opt = 0x01;  // Update ISO File ID
    if (second) {
        file_opt |= 0x02;  // Update two files
    }
    data.push_back(file_opt);
    data.push_back(first.old_file_no);
    data.push_back(first.new_file_no);
    data.push_back(static_cast<uint8_t>(first.new_file_id & 0xFF));
    data.push_back(static_cast<uint8_t>((first.new_file_id >> 8) & 0xFF));
    if (second) {
        data.push_back(second->old_file_no);
        data.push_back(second->new_file_no);
        data.push_back(static_cast<uint8_t>(second->new_file_id & 0xFF));
        data.push_back(static_cast<uint8_t>((second->new_file_id >> 8) & 0xFF));
    }

    const uint8_t cmd_header[1] = {0x08};
    return transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_SET_CONFIGURATION), cmd_header,
                              sizeof(cmd_header), data.data(), data.size(), ctx, nullptr);
}

bool DESFireFileSystem::setConfigurationAppNameEV2Full(const uint8_t* df_name, uint8_t df_name_len, uint16_t iso_fid,
                                                       Ev2Context& ctx)
{
    if (!df_name || df_name_len == 0 || df_name_len > 16) {
        return false;
    }

    std::vector<uint8_t> data{};
    data.reserve(1 + 16 + 2);
    const uint8_t app_opt = static_cast<uint8_t>(0x80 | (df_name_len & 0x1F));  // bit7=1 + name length
    data.push_back(app_opt);
    for (uint8_t i = 0; i < 16; ++i) {
        data.push_back((i < df_name_len) ? df_name[i] : 0x00);
    }
    data.push_back(static_cast<uint8_t>(iso_fid & 0xFF));  // LSB first
    data.push_back(static_cast<uint8_t>((iso_fid >> 8) & 0xFF));

    const uint8_t cmd_header[1] = {0x06};
    return transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_SET_CONFIGURATION), cmd_header,
                              sizeof(cmd_header), data.data(), data.size(), ctx, nullptr);
}

bool DESFireFileSystem::deleteTransactionMACFileEV2Full(const uint8_t file_no, Ev2Context& ctx)
{
    // DeleteTransactionMACFile: CmdHeader = FileNo, CmdData = none
    // This command deletes the TMAC file, which is required for ISOReadBinary to work on DESFire Light
    const uint8_t cmd_header[1] = {file_no};
    return transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_DELETE_TRANSACTION_MAC_FILE), cmd_header,
                              sizeof(cmd_header), nullptr, 0, ctx, nullptr);
}

bool DESFireFileSystem::createTransactionMACFileEV2Full(const uint8_t file_no, const uint8_t comm_mode,
                                                        const uint16_t access_rights, const uint8_t tmac_key[16],
                                                        const uint8_t tmac_key_ver, Ev2Context& ctx)
{
    // CreateTransactionMACFile:
    // CmdHeader = FileNo + FileOption + AccessRights + TMACKeyOption (5 bytes)
    // CmdData = TMACKey + TMACKeyVer (17 bytes, encrypted)
    uint8_t cmd_header[5];
    cmd_header[0] = file_no;
    cmd_header[1] = comm_mode & 0x03;                                   // FileOption (CommMode in bits 1-0)
    cmd_header[2] = static_cast<uint8_t>(access_rights & 0xFF);         // AccessRights LSB
    cmd_header[3] = static_cast<uint8_t>((access_rights >> 8) & 0xFF);  // AccessRights MSB
    cmd_header[4] = 0x02;                                               // TMACKeyOption: 02h = AES key

    std::vector<uint8_t> data;
    data.reserve(16 + 1);
    for (int i = 0; i < 16; ++i) {
        data.push_back(tmac_key[i]);
    }
    data.push_back(tmac_key_ver);
    return transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_CREATE_TRANSACTION_MAC_FILE), cmd_header,
                              sizeof(cmd_header), data.data(), data.size(), ctx, nullptr);
}

bool DESFireFileSystem::getFileIDs(std::vector<uint8_t>& out)
{
    out.clear();
    auto cmd = make_native_wrap_command(m5::stl ::to_underlying(INS::DF_GET_FILE_IDS));

    std::vector<uint8_t> rx(MAXIMUM_FILES + 2);
    uint16_t rx_len = rx.size();
    if (!transceive(rx.data(), rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to getFileIDs %u", rx_len);
        return false;
    }
    if (is_successful(rx.data(), rx_len)) {
        const uint16_t data_len = rx_len - 2;
        if (data_len > MAXIMUM_FILES) {
            M5_LIB_LOGW("getFileIDs: secured response not supported");
            return false;
        }
        out.assign(rx.begin(), rx.begin() + data_len);
        return true;
    }
    M5_LIB_LOGE("getFileIDs failed status %02X", status_code(rx.data(), rx_len));
    return false;
}

bool DESFireFileSystem::getISOFileIDs(std::vector<uint8_t>& out)
{
    out.clear();
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_ISO_FILE_IDS));

    // ISO File IDs are 2 bytes each, max 32 files = 64 bytes + status
    std::vector<uint8_t> rx(MAXIMUM_FILES * 2 + 2);
    uint16_t rx_len = rx.size();
    if (!transceive(rx.data(), rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to getISOFileIDs %u", rx_len);
        return false;
    }
    if (is_successful(rx.data(), rx_len)) {
        const uint16_t data_len = rx_len - 2;
        out.assign(rx.begin(), rx.begin() + data_len);
        return true;
    }
    return false;
}

bool DESFireFileSystem::getFileSettings(FileSettings& out, const uint8_t file_no)
{
    out      = {};
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_FILE_SETTINGS), &file_no, 1);

    uint8_t rx[32]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (!is_successful(rx, rx_len)) {
        return false;
    }
    const uint16_t data_len = static_cast<uint16_t>(rx_len - 2);
    if (data_len < 4) {
        return false;
    }
    const uint8_t file_type = rx[0];
    if (file_type == 0x05) {  // TransactionMAC file
        const uint8_t file_option = rx[1];
        out.file_type     = file_type;
        out.comm_mode     = (file_option & 0x03);
        out.access_rights = static_cast<uint16_t>(rx[2]) | (static_cast<uint16_t>(rx[3]) << 8);
        out.file_size     = 0;
        return true;
    }
    if (data_len < 7) {
        return false;
    }
    //    if (data_len > 7) {
    //        M5_LIB_LOGW("getFileSettings: secured response not supported");
    //    }
    out.file_type     = file_type;
    out.comm_mode     = rx[1];
    out.access_rights = static_cast<uint16_t>(rx[2]) | (static_cast<uint16_t>(rx[3]) << 8);
    out.file_size     = unpack_le24(rx + 4);
    return true;
}

bool DESFireFileSystem::getFileSettingsEV2(FileSettings& out, const uint8_t file_no, Ev2Context& ctx)
{
    out = {};
    std::vector<uint8_t> resp;
    if (!transceive_sm_mac(_isoDEP, m5::stl::to_underlying(INS::DF_GET_FILE_SETTINGS), &file_no, 1, nullptr, 0, ctx,
                           &resp)) {
        return false;
    }
    if (resp.size() < 4) {
        return false;
    }
    const uint8_t file_type = resp[0];
    if (file_type == 0x05) {  // TransactionMAC file
        const uint8_t file_option = resp[1];
        out.file_type     = file_type;
        out.comm_mode     = (file_option & 0x03);
        out.access_rights = static_cast<uint16_t>(resp[2]) | (static_cast<uint16_t>(resp[3]) << 8);
        out.file_size     = 0;
        return true;
    }
    if (resp.size() < 7) {
        return false;
    }
    out.file_type     = file_type;
    out.comm_mode     = resp[1];
    out.access_rights = static_cast<uint16_t>(resp[2]) | (static_cast<uint16_t>(resp[3]) << 8);
    out.file_size     = unpack_le24(resp.data() + 4);
    return true;
}

bool DESFireFileSystem::getFileSettingsEV2Full(FileSettings& out, const uint8_t file_no, Ev2Context& ctx)
{
    out = {};
    std::vector<uint8_t> resp;
    if (!transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_GET_FILE_SETTINGS), &file_no, 1, nullptr, 0, ctx,
                            &resp)) {
        return false;
    }
    if (resp.size() < 4) {
        return false;
    }
    const uint8_t file_type = resp[0];
    if (file_type == 0x05) {  // TransactionMAC file
        const uint8_t file_option = resp[1];
        out.file_type     = file_type;
        out.comm_mode     = (file_option & 0x03);
        out.access_rights = static_cast<uint16_t>(resp[2]) | (static_cast<uint16_t>(resp[3]) << 8);
        out.file_size     = 0;
        return true;
    }
    if (resp.size() < 7) {
        return false;
    }
    out.file_type     = file_type;
    out.comm_mode     = resp[1];
    out.access_rights = static_cast<uint16_t>(resp[2]) | (static_cast<uint16_t>(resp[3]) << 8);
    out.file_size     = unpack_le24(resp.data() + 4);
    return true;
}

bool DESFireFileSystem::changeFileSettingsEV2Full(const uint8_t file_no, const uint8_t file_option,
                                                  const uint16_t access_rights, Ev2Context& ctx)
{
    // FileNo is in header (plain), FileOption + AccessRights are in data (encrypted)
    uint8_t header[1] = {file_no};
    uint8_t data[1 + 2]{};
    data[0] = file_option;
    data[1] = static_cast<uint8_t>(access_rights & 0xFF);
    data[2] = static_cast<uint8_t>((access_rights >> 8) & 0xFF);
    return transceive_sm_full(_isoDEP, m5::stl::to_underlying(INS::DF_CHANGE_FILE_SETTINGS), header, sizeof(header),
                              data, sizeof(data), ctx, nullptr);
}

bool DESFireFileSystem::changeFileSettingsEV2(const uint8_t file_no, const uint8_t file_option,
                                              const uint16_t access_rights, Ev2Context& ctx)
{
    // FileNo is in header, FileOption + AccessRights are in data
    uint8_t header[1] = {file_no};
    uint8_t data[1 + 2]{};
    data[0] = (file_option & 0x03);
    data[1] = static_cast<uint8_t>(access_rights & 0xFF);
    data[2] = static_cast<uint8_t>((access_rights >> 8) & 0xFF);
    return transceive_sm_mac(_isoDEP, m5::stl::to_underlying(INS::DF_CHANGE_FILE_SETTINGS), header, sizeof(header),
                             data, sizeof(data), ctx, nullptr);
}

bool DESFireFileSystem::changeFileSettings(const uint8_t file_no, const uint8_t file_option,
                                           const uint16_t access_rights)
{
    uint8_t data[1 + 1 + 2]{};
    uint8_t* p = data;
    *p++       = file_no;
    *p++       = (file_option & 0x03);
    *p++       = static_cast<uint8_t>(access_rights & 0xFF);
    *p++       = static_cast<uint8_t>((access_rights >> 8) & 0xFF);

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_CHANGE_FILE_SETTINGS), data, sizeof(data));

    uint8_t rx[16]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        return false;
    }
    if (is_successful(rx, rx_len)) {
        return true;
    }
    M5_LIB_LOGE("ChangeFileSettings failed (%02X)", status_code(rx, rx_len));
    return false;
}

bool DESFireFileSystem::authenticateDES(const uint8_t key_no, const uint8_t key[16])
{
    return authenticate_legacy(_isoDEP, m5::stl::to_underlying(INS::DF_AUTHENTICATE), key_no, key);
}

bool DESFireFileSystem::authenticateISO(const uint8_t key_no, const uint8_t key[16])
{
    return authenticate_legacy(_isoDEP, m5::stl::to_underlying(INS::DF_AUTHENTICATE_ISO), key_no, key);
}

bool DESFireFileSystem::authenticateAES(const uint8_t key_no, const uint8_t key[16])
{
    if (!key) {
        return false;
    }

    uint8_t auth_key_no[1] = {key_no};
    auto cmd               = make_native_wrap_command(m5::stl::to_underlying(INS::DF_AUTHENTICATE_AES), auth_key_no, 1);

    std::vector<uint8_t> rx(DEFAULT_RX_LEN);
    uint16_t rx_len = rx.size();
    if (!_isoDEP.transceiveINF(rx.data(), rx_len, cmd.data(), cmd.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth AES step1 %u", rx_len);
        return false;
    }
    if (!is_more(rx.data(), rx_len) || rx_len < 18) {
        M5_LIB_LOGE("Unexpected auth AES step1 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }

    uint8_t ek_rndB[16]{};
    std::memcpy(ek_rndB, rx.data(), 16);

    uint8_t rndB[16]{};
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key, 128);
        uint8_t iv[16]{};
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, ek_rndB, rndB);
        mbedtls_aes_free(&aes);
    }

    uint8_t rndB_rot[16]{};
    for (int i = 0; i < 15; ++i) {
        rndB_rot[i] = rndB[i + 1];
    }
    rndB_rot[15] = rndB[0];

    uint8_t rndA[16]{};
    for (auto& r : rndA) {
        r = static_cast<uint8_t>(esp_random());
    }

    uint8_t plain_AB[32]{};
    std::memcpy(plain_AB, rndA, 16);
    std::memcpy(plain_AB + 16, rndB_rot, 16);

    uint8_t ek_AB[32]{};
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key, 128);
        uint8_t iv[16]{};
        std::memcpy(iv, ek_rndB, 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(plain_AB), iv, plain_AB, ek_AB);
        mbedtls_aes_free(&aes);
    }

    auto cmd2 = make_native_wrap_command(0xAF, ek_AB, sizeof(ek_AB));
    rx_len    = rx.size();
    if (!_isoDEP.transceiveINF(rx.data(), rx_len, cmd2.data(), cmd2.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth AES step2 %u", rx_len);
        return false;
    }
    if (!is_successful(rx.data(), rx_len) || rx_len < 18) {
        M5_LIB_LOGE("Unexpected auth AES step2 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }

    uint8_t rndA_rot_from_card[16]{};
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, key, 128);
        uint8_t iv[16]{};
        std::memcpy(iv, ek_AB + 16, 16);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, rx.data(), rndA_rot_from_card);
        mbedtls_aes_free(&aes);
    }

    uint8_t rndA_rot[16]{};
    for (int i = 0; i < 15; ++i) {
        rndA_rot[i] = rndA[i + 1];
    }
    rndA_rot[15] = rndA[0];

    return std::memcmp(rndA_rot, rndA_rot_from_card, 16) == 0;
}

bool DESFireFileSystem::authenticateEV2First(const uint8_t key_no, const uint8_t key[16], Ev2Context& ctx)
{
    if (!key) {
        return false;
    }

    uint8_t data[2]{};
    data[0] = key_no;
    data[1] = 0x00;  // LenCap=0 (no PCDcap2), per AN12343 example

    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_AUTHENTICATE_EV2), data, sizeof(data));

    std::vector<uint8_t> rx(DEFAULT_RX_LEN);
    uint16_t rx_len = rx.size();
    if (!_isoDEP.transceiveINF(rx.data(), rx_len, cmd.data(), cmd.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth EV2 step1 %u", rx_len);
        return false;
    }
    if (!is_more(rx.data(), rx_len)) {
        M5_LIB_LOGE("Unexpected auth EV2 step1 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }
    const uint16_t data_len = static_cast<uint16_t>(rx_len - 2);
    if (data_len == 17) {
        M5_LIB_LOGE("auth EV2 step1 LRP response");
        return false;
    }
    if (data_len != 16) {
        M5_LIB_LOGE("auth EV2 step1 length %u", data_len);
        return false;
    }

    uint8_t ek_rndB[16]{};
    std::memcpy(ek_rndB, rx.data(), 16);

    uint8_t rndB[16]{};
    uint8_t iv0[16]{};
    aes_cbc_crypt(key, iv0, ek_rndB, rndB, sizeof(rndB), false);

    uint8_t rndB_rot[16]{};
    for (int i = 0; i < 15; ++i) {
        rndB_rot[i] = rndB[i + 1];
    }
    rndB_rot[15] = rndB[0];

    uint8_t rndA[16]{};
    for (auto& r : rndA) {
        r = static_cast<uint8_t>(esp_random());
    }

    uint8_t plain_AB[32]{};
    std::memcpy(plain_AB, rndA, 16);
    std::memcpy(plain_AB + 16, rndB_rot, 16);

    uint8_t ek_AB[32]{};
    aes_cbc_crypt(key, iv0, plain_AB, ek_AB, sizeof(plain_AB), true);

    auto cmd2 = make_native_wrap_command(0xAF, ek_AB, sizeof(ek_AB));
    rx_len    = rx.size();
    if (!_isoDEP.transceiveINF(rx.data(), rx_len, cmd2.data(), cmd2.size(), nullptr) || rx_len < 2) {
        M5_LIB_LOGE("Failed to auth EV2 step2 %u", rx_len);
        return false;
    }
    if (!is_successful(rx.data(), rx_len)) {
        M5_LIB_LOGE("Unexpected auth EV2 step2 status %02X %02X", rx[rx_len - 2], rx[rx_len - 1]);
        return false;
    }
    const uint16_t data_len2 = static_cast<uint16_t>(rx_len - 2);
    if (data_len2 != 32) {
        M5_LIB_LOGE("auth EV2 step2 data length %u", data_len2);
        return false;
    }

    uint8_t plain_resp[32]{};
    aes_cbc_crypt(key, iv0, rx.data(), plain_resp, sizeof(plain_resp), false);

    std::memcpy(ctx.ti, plain_resp, sizeof(ctx.ti));
    uint8_t rndA_rot_from_card[16]{};
    std::memcpy(rndA_rot_from_card, plain_resp + 4, 16);
    for (int i = 0; i < 16; ++i) {
        if (rndA_rot_from_card[i] != rndA[(i + 1) % 16]) {
            return false;
        }
    }

    ctx.cmd_ctr = 0;
    uint8_t sv1[32]{};
    uint8_t sv2[32]{};
    build_sv(0xA5, 0x5A, rndA, rndB, sv1);
    build_sv(0x5A, 0xA5, rndA, rndB, sv2);
    cmac_aes_128(key, sv1, sizeof(sv1), ctx.ses_enc_key);
    cmac_aes_128(key, sv2, sizeof(sv2), ctx.ses_mac_key);
    return true;
}

// Support continued reception via 0x91AF
bool DESFireFileSystem::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len)
{
    const auto org_rx_len = rx_len;
    rx_len                = 0;
    if (!rx || org_rx_len < 2 || !tx || tx_len < 4) {
        return false;
    }

    // m5::utility::log::dump(tx, tx_len, false);

    std::vector<uint8_t> acc;
    acc.reserve(org_rx_len);

    std::vector<uint8_t> tmp_rx(org_rx_len);
    uint16_t tmp_rx_len = org_rx_len;

    // First
    if (!_isoDEP.transceiveINF(tmp_rx.data(), tmp_rx_len, tx, tx_len) || tmp_rx_len < 2) {
        M5_LIB_LOGE("Failed to transceiveINF %u", tmp_rx_len);
        M5_DUMPE(tmp_rx.data(), tmp_rx_len);
        return false;
    }

    if (tmp_rx_len > 2) {
        if (acc.size() + (tmp_rx_len - 2) + 2 /*status 2bytes*/ > org_rx_len) {
            return false;
        }
        acc.insert(acc.end(), tmp_rx.begin(), tmp_rx.begin() + (tmp_rx_len - 2));
    }

    constexpr uint8_t af_cmd[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    constexpr uint8_t MAX_AF_FOLLOW{32};
    uint8_t af_follow{};

    while (is_more(tmp_rx.data(), tmp_rx_len)) {
        if (++af_follow > MAX_AF_FOLLOW) {
            return false;
        }
        tmp_rx_len = org_rx_len;
        // More response please!
        if (!_isoDEP.transceiveINF(tmp_rx.data(), tmp_rx_len, af_cmd, sizeof(af_cmd)) || tmp_rx_len < 2) {
            M5_LIB_LOGE("Failed to transceiveINF %u", tmp_rx_len);
            M5_DUMPE(tmp_rx.data(), tmp_rx_len);
            return false;
        }
        // m5::utility::log::dump(tmp_rx.data(), tmp_rx_len, false);
        if (tmp_rx_len > 2) {
            if (acc.size() + (tmp_rx_len - 2) + 2 /*status 2bytes*/ > org_rx_len) {
                return false;
            }
            acc.insert(acc.end(), tmp_rx.begin(), tmp_rx.begin() + (tmp_rx_len - 2));
        }
    }
    acc.push_back(tmp_rx[tmp_rx_len - 2]);
    acc.push_back(tmp_rx[tmp_rx_len - 1]);
    if (acc.size() > org_rx_len) {
        return false;
    }

    rx_len = acc.size();
    std::memcpy(rx, acc.data(), rx_len);
    return true;
}

}  // namespace desfire
}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
