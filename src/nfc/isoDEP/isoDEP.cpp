/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file isoDEP.cpp
  @brief ISO Data Exchange Protocol
*/
#include "isoDEP.hpp"
#include "nfc/layer/nfc_layer.hpp"
#include "nfc/apdu/apdu.hpp"
#include <M5Utility.hpp>
#include <algorithm>
#include <cstring>
#include <limits>

using namespace m5::nfc::apdu;

namespace {
using namespace m5::nfc::isodep::detail;

std::vector<uint8_t> remake_with_le(std::vector<uint8_t>& org, const uint16_t new_le)
{
    uint32_t org_len = org.size();

    if (org_len < 4) {
        return org;
    }
    uint8_t cla = org[0];
    uint8_t ins = org[1];
    uint8_t p1  = org[2];
    uint8_t p2  = org[3];
    uint16_t lc{};
    uint8_t* data{};

    if (org_len == 4) {                                    // Case 1:[CLA INS P1 P2]
        return make_apdu_case2(cla, ins, p1, p2, new_le);  // Change to Case 2
    }

    if (org_len == 5) {  // Case 2: [CLA INS P1 P2 Le1]
        return make_apdu_case2(cla, ins, p1, p2, new_le);
    }
    if (org_len == 7 && org[4] == 0x00) {  // Case 2: [CLA INS P1 P2 00 Le3]
        return make_apdu_case2(cla, ins, p1, p2, new_le);
    }

    // short Lc: org[4] != 0x00, Lc=org[4]
    if (org_len >= 5 && org[4] != 0x00) {
        lc                      = org[4];
        const uint16_t data_off = 5;
        if (org_len < data_off + lc) {
            return org;
        }
        data                = (lc ? (org.data() + data_off) : nullptr);
        const uint16_t rest = org_len - (data_off + lc);
        if (rest == 0) {  // Case 3: [CLA INS P1 P2 Lc1 Data]
            return make_apdu_case4(cla, ins, p1, p2, data, lc, new_le);
        }
        if (rest == 1) {  // Case 4: [CLA INS P1 P2 Lc1 Data] Le]
            return make_apdu_case4(cla, ins, p1, p2, data, lc, new_le);
        }
        return org;
    }

    // extended Lc cases: [CLA INS P1 P2 00 LcHi LcLo ...]
    if (org_len >= 7 && org[4] == 0x00) {
        lc                      = (uint16_t)((org[5] << 8) | org[6]);
        const uint16_t data_off = 7;
        if (org_len < data_off + lc) {
            return org;
        }
        data                = lc ? (org.data() + data_off) : nullptr;
        const uint16_t rest = (uint16_t)(org_len - (data_off + lc));
        if (rest == 0) {  // Case 3: [CLA INS P1 P2 Lc3 Data]
            return make_apdu_case4(cla, ins, p1, p2, data, lc, new_le);
        }
        if (rest == 3) {  // Case 4: [CLA INS P1 P2 Lc3 Data] Le]
            return make_apdu_case4(cla, ins, p1, p2, data, lc, new_le);
        }
        return {};
    }
    return org;
}

}  // namespace

namespace m5 {
namespace nfc {
namespace isodep {

uint32_t fwi_to_ms(const uint8_t fwi, const float fc)
{
    if (fwi >= 15) {
        return 0;
    }
    const uint8_t fwi_eff = (fwi == 0) ? 1 : fwi;
    const float base_us   = (4096.0f / fc) * 1e6f;
    const float fwt_us    = base_us * static_cast<float>(1u << fwi_eff);
    uint32_t fwt_ms       = static_cast<uint32_t>(fwt_us / 1000.f);
    return (fwt_ms != 0) ? fwt_ms : 1;
}

// #define ENABLE_PRINT_ERROR
#if defined(ENABLE_PRINT_ERROR)
#define PRINT_ERROR(...) M5_LIB_LOGE(__VA_ARGS__)
#else
#define PRINT_ERROR(...) /* Nop */
#endif

bool IsoDEP::transceiveINF(uint8_t* rx_inf, uint16_t& rx_inf_len, const uint8_t* tx_inf, const uint16_t tx_inf_len,
                           RxInfo* pinfo)
{
    const uint16_t rx_inf_len_org = rx_inf_len;
    RxInfo infoTmp{};
    RxInfo* info = pinfo ? pinfo : &infoTmp;
    *info        = {};
    rx_inf_len   = 0;
    if (!rx_inf || !rx_inf_len_org || !tx_inf || !tx_inf_len) {
        return false;
    }

    // Calculate the maximum amount of INF that can fit within the frame
    // FSC is the max frame size (including prologue: PCB, CID, NAD) the card can receive
    const uint16_t tx_frame_cap = _cfg.max_frame_cap_tx();
    const uint16_t max_frame_size_rx =
        std::min<uint16_t>(_cfg.max_frame_size_rx(), _layer.maximum_fifo_depth() - 2 /*CRC*/);
    // FSC includes prologue, so max INF = FSC - overhead
    const uint16_t fsc_inf_cap       = _cfg.fsc_inf_cap();
    const uint16_t max_inf_per_frame = std::min(tx_frame_cap, fsc_inf_cap);

    // M5_LIB_LOGV("cap:%u fcs:%u per:%u", tx_frame_cap, fsc_inf_cap, max_inf_per_frame);

    if (max_inf_per_frame == 0) {
        return false;
    }

    const uint16_t rx_overhead_min = _cfg.overhead();
    uint8_t tx_buf[MAX_FRAME_SIZE]{};
    uint8_t rx_buf[MAX_FRAME_SIZE]{};
    uint16_t tx_off{};
    uint16_t rx_written{};

    // Transmit chaining
    while (tx_off < tx_inf_len) {
        const uint16_t remain = tx_inf_len - tx_off;
        const uint16_t chunk  = (remain > max_inf_per_frame) ? max_inf_per_frame : remain;
        const bool more       = (tx_off + chunk) < tx_inf_len;

        // Build I-Block
        uint16_t tpos  = 0;
        tx_buf[tpos++] = make_i_pcb(_block_num, more, _cfg.use_cid, _cfg.use_nad);
        if (_cfg.use_cid) {
            tx_buf[tpos++] = (uint8_t)(_cfg.cid & 0x0F);
        }
        if (_cfg.use_nad) {
            tx_buf[tpos++] = _cfg.nad;
        }
        memcpy(tx_buf + tpos, tx_inf + tx_off, chunk);
        tpos += chunk;

        bool chunk_done = false;
        uint8_t retries = 0;

        while (!chunk_done) {
            // Note: FSC is the card's receive limit, not its send limit.
            // The card can send frames larger than FSC, so use full PCD receive capacity.
            uint16_t rlen             = max_frame_size_rx;
            const uint32_t timeout_ms = _cfg.fwt_ms;

            // Send I-Block and receive first frame
            // M5_LIB_LOGE("I-Block TX: %u bytes, timeout=%u", tpos, timeout_ms);
            if (!_layer.transceive(rx_buf, rlen, tx_buf, tpos, timeout_ms)) {
                M5_LIB_LOGE("transceive failed, rlen=%u", rlen);
                if (rlen > 0) {
                    M5_LIB_LOGE("RX: %02X %02X %02X %02X", rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3]);
                }
                // if (retries++ < _cfg.max_retries) continue;
                rx_inf_len = rlen;
                memcpy(rx_inf, rx_buf, rlen);
                PRINT_ERROR(">>>>ERROR 1 %u %02X", rlen, rx_buf[0]);
                return false;
            }

            // Parse loop: WTX can replace rx_buf/rlen and we continue parsing without re-sending I-Block.
            for (;;) {
                if (rlen < 1) {
                    if (retries++ < _cfg.max_retries) {
                        // resend I-Block
                        break;
                    }
                    PRINT_ERROR(">>>>ERROR 2");
                    return false;
                }
                if (_cfg.rx_crc && rlen >= 3) {
                    rlen -= 2;
                }

                // (5) Minimum header check
                if (rlen < rx_overhead_min) {
                    if (retries++ < _cfg.max_retries) {
                        // resend I-Block
                        break;
                    }
                    PRINT_ERROR(">>>>ERROR 3");
                    return false;
                }

                const uint8_t pcb = rx_buf[0];

                // --- S-Block (WTX) ---
                if (is_s_wtx(pcb)) {
                    info->wtx_seen = true;

                    if (rlen < (uint16_t)(rx_overhead_min + 1)) {
                        if (retries++ < _cfg.max_retries) {
                            break;  // resend I-Block
                        }
                        PRINT_ERROR(">>>>ERROR 4");
                        return false;
                    }

                    const uint8_t wtxm = get_wtxm(rx_buf[rx_overhead_min]);
                    if (!is_valid_wtxm(wtxm)) {
                        PRINT_ERROR(">>>>ERROR 5");
                        return false;
                    }

                    uint8_t s_ack[3]{};
                    uint16_t sp = 0;
                    s_ack[sp++] = make_s_wtx_ack(_cfg.use_cid);
                    if (_cfg.use_cid) s_ack[sp++] = (uint8_t)(_cfg.cid & 0x0F);
                    s_ack[sp++] = wtxm;  // echo

                    const uint32_t wtx_timeout = mul_clamp_u32(_cfg.fwt_ms, (uint32_t)wtxm, _cfg.wtx_max_ms);

                    // Receive next frame after WTX-ACK (do NOT resend I-Block)
                    rlen = sizeof(rx_buf);
                    if (!_layer.transceive(rx_buf, rlen, s_ack, sp, wtx_timeout)) {
                        if (retries++ < _cfg.max_retries) {
                            break;  // resend I-Block
                        }
                        PRINT_ERROR(">>>>ERROR 6");
                        return false;
                    }
                    // Parse the newly received frame in the same loop
                    continue;
                }

                // --- other S-Block (not supported) ---
                if (is_s_block(pcb)) {
                    if (retries++ < _cfg.max_retries) {
                        break;  // resend I-Block
                    }
                    PRINT_ERROR(">>>>ERROR 7");
                    return false;
                }

                // --- R-Block ---
                if (is_r_block(pcb)) {
                    if (!is_valid_rblock(pcb)) {
                        if (retries++ < _cfg.max_retries) {
                            break;  // resend I-Block
                        }
                        PRINT_ERROR(">>>>ERROR 8");
                        return false;
                    }

                    if (r_is_nak(pcb)) {
                        if (retries++ < _cfg.max_retries) {
                            break;  // resend I-Block
                        }
                        PRINT_ERROR(">>>>ERROR 9");
                        return false;
                    }

                    // ACK (chaining) -> next chunk
                    if (r_is_ack(pcb) && more) {
                        chunk_done = true;
                        break;
                    }

                    // ACK but more==false: resend I-Block conservatively
                    if (retries++ < _cfg.max_retries) {
                        break;
                    }
                    PRINT_ERROR(">>>>ERROR 10");
                    return false;
                }

                // --- I-Block ---
                if (is_i_block(pcb)) {
                    uint16_t idx = 1;
                    if (_cfg.use_cid) idx++;
                    if (_cfg.use_nad) idx++;
                    if (rlen < idx) {
                        PRINT_ERROR(">>>>ERROR 11");
                        return false;
                    }

                    const uint16_t inf_len = (uint16_t)(rlen - idx);
                    if (rx_written + inf_len > rx_inf_len_org) {
                        PRINT_ERROR("rx_written %u inf_len %u rx_inf_len %u", rx_written, inf_len, rx_inf_len_org);
                        // m5::utility::log::dump(rx_inf, rx_written, false);
                        return false;
                    }

                    memcpy(rx_inf + rx_written, rx_buf + idx, inf_len);
                    rx_written = (uint16_t)(rx_written + inf_len);

                    bool resp_more = i_has_more(pcb);
                    info->more     = resp_more;

                    // Response chaining: send R-ACK and receive next I-Block (WTX may appear)
                    while (resp_more) {
                        uint8_t r_ack[2]{};
                        uint16_t rp = 0;
                        r_ack[rp++] = make_r_ack(i_bn(pcb), _cfg.use_cid);
                        if (_cfg.use_cid) r_ack[rp++] = (uint8_t)(_cfg.cid & 0x0F);

                        uint16_t rlen2 = sizeof(rx_buf);
                        if (!_layer.transceive(rx_buf, rlen2, r_ack, rp, _cfg.fwt_ms)) {
                            PRINT_ERROR(">>>>ERROR 12");
                            return false;
                        }

                        for (;;) {
                            if (_cfg.rx_crc && rlen2 >= 3) rlen2 -= 2;
                            if (rlen2 < rx_overhead_min) return false;

                            const uint8_t pcb2 = rx_buf[0];

                            // If any S-Block other than WTX exists within the chain,
                            // it shall be treated as unsupported and result in failure.
                            if (is_s_block(pcb2) && !is_s_wtx(pcb2)) {
                                PRINT_ERROR(">>>>ERROR 13");
                                return false;
                            }

                            if (is_s_wtx(pcb2)) {
                                info->wtx_seen = true;

                                if (rlen2 < (uint16_t)(rx_overhead_min + 1)) return false;
                                const uint8_t wtxm = get_wtxm(rx_buf[rx_overhead_min]);
                                if (!is_valid_wtxm(wtxm)) return false;

                                uint8_t s_ack[3]{};
                                uint16_t sp = 0;
                                s_ack[sp++] = make_s_wtx_ack(_cfg.use_cid);
                                if (_cfg.use_cid) s_ack[sp++] = (uint8_t)(_cfg.cid & 0x0F);
                                s_ack[sp++] = wtxm;

                                const uint32_t wtx_timeout =
                                    mul_clamp_u32(_cfg.fwt_ms, (uint32_t)wtxm, _cfg.wtx_max_ms);

                                rlen2 = sizeof(rx_buf);
                                if (!_layer.transceive(rx_buf, rlen2, s_ack, sp, wtx_timeout)) {
                                    PRINT_ERROR(">>>>ERROR 14");
                                    return false;
                                }
                                continue;
                            }

                            if (is_r_block(pcb2)) {
                                if (!is_valid_rblock(pcb2)) return false;
                                if (r_is_nak(pcb2)) return false;

                                // ACK: receive again
                                rlen2 = sizeof(rx_buf);
                                if (!_layer.receive(rx_buf, rlen2, _cfg.fwt_ms)) {
                                    PRINT_ERROR(">>>>ERROR 15");
                                    return false;
                                }
                                continue;
                            }

                            if (!is_i_block(pcb2)) return false;

                            uint16_t idx2 = 1 + (_cfg.use_cid ? 1 : 0) + (_cfg.use_nad ? 1 : 0);
                            if (rlen2 < idx2) return false;

                            const uint16_t inf_len2 = (uint16_t)(rlen2 - idx2);
                            if (rx_written + inf_len2 > rx_inf_len_org) {
                                PRINT_ERROR("rx_written %u inf_len2 %u rx_inf_len %u", rx_written, inf_len2,
                                            rx_inf_len);
                                // m5::utility::log::dump(rx_inf, rx_written, false);

                                return false;
                            }

                            memcpy(rx_inf + rx_written, rx_buf + idx2, inf_len2);
                            rx_written = (uint16_t)(rx_written + inf_len2);

                            resp_more = i_has_more(pcb2);
                            break;
                        }
                    }

                    // This chunk is completed
                    chunk_done = true;
                    break;
                }

                // Unknown frame type
                if (retries++ < _cfg.max_retries) {
                    break;  // resend I-Block
                }
                return false;
            }
        }

        // next chunk
        tx_off = (uint16_t)(tx_off + chunk);
        _block_num ^= 1;
    }

    rx_inf_len = rx_written;

    // M5_LIB_LOGE(">>>> INF %u", rx_inf_len);
    // m5::utility::log::dump(rx_inf, rx_inf_len, false);
    return true;
}

bool IsoDEP::transceiveAPDU(uint8_t* rx, uint16_t& rx_len, const uint8_t* cmd, const uint16_t cmd_len)
{
    if (!rx || rx_len < 2 || !cmd || cmd_len < 4) {
        return false;
    }

    // M5_LIB_LOGE(">>>> APDU");
    // m5::utility::log::dump(cmd, cmd_len, false);

    // Save original command
    const uint8_t* orig_cmd = cmd;
    // const uint16_t orig_cmd_len = cmd_len;

    // Cmd buffer
    std::vector<uint8_t> cur_cmd(cmd, cmd + cmd_len);

    // buffer for 0x61
    std::vector<uint8_t> acc{};
    acc.reserve(256);

    constexpr uint8_t MAX_FOLLOW_61{8};
    constexpr uint8_t MAX_RETRY_6C{2};
    uint8_t follow61{}, retry6c{};
    uint8_t sw1{}, sw2{};

    for (;;) {
        std::vector<uint8_t> tmp;
        tmp.resize(rx_len);
        uint16_t tmp_len = static_cast<uint16_t>(std::min<size_t>(tmp.size(), std::numeric_limits<uint16_t>::max()));

        if (!transceiveINF(tmp.data(), tmp_len, cur_cmd.data(), cur_cmd.size(), nullptr)) {
            return false;
        }
        tmp.resize(tmp_len);
        if (tmp.size() < 2) {
            return false;
        }
        acc.insert(acc.end(), tmp.begin(), tmp.end() - 2 /* SW*/);

        sw1 = tmp[tmp.size() - 2];
        sw2 = tmp[tmp.size() - 1];

        // 6Cxx: Wrong Le
        if (sw1 == 0x6C) {
            if (retry6c++ >= MAX_RETRY_6C) {
                break;
            }

            const uint16_t new_le = (sw2 == 0x00) ? 256 : sw2;
            auto cmd2             = remake_with_le(cur_cmd, new_le);
            if (cmd2.empty()) {
                return false;
            }
            // Purge acc
            acc.clear();
            cur_cmd = std::move(cmd2);
            continue;
        }

        // 61xx: More data
        if (sw1 == 0x61) {
            if (follow61++ >= MAX_FOLLOW_61) {
                break;
            }

            const uint16_t le = (sw2 == 0x00) ? 256 : sw2;
            auto cmd2 =
                make_apdu_command(orig_cmd[0], m5::stl::to_underlying(INS::GET_RESPONSE), 0x00, 0x00, nullptr, 0, le);
            if (cmd2.empty()) {
                return false;
            }
            // Keep acc
            cur_cmd = std::move(cmd2);
            continue;
        }

        // OK or error
        break;
    }
    const uint16_t need = acc.size() + 2 /*SW*/;
    if (need > rx_len) {
        return false;
    }
    if (!acc.empty()) {
        std::memcpy(rx, acc.data(), acc.size());
    }
    rx[acc.size() + 0] = sw1;
    rx[acc.size() + 1] = sw2;
    rx_len             = need;
    return true;
}

bool IsoDEP::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                        const uint32_t timeout_ms)
{
    return _layer.transceive(rx, rx_len, tx, tx_len, timeout_ms);
}

}  // namespace isodep
}  // namespace nfc
}  // namespace m5
