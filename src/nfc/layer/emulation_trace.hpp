/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_trace.hpp
  @brief State trace shared by the emulation adapters

  @note Recording only writes to memory, so it can be used where the emulation has to answer the
  reader in time. Printing is left to the caller, which does it while no session is running
  @note Repeats of the same event are folded into a count, because a reader polling a halted PICC
  produces the same entry dozens of times and those would push the interesting ones out
  @note The buffer keeps the newest entries: a failure shows up at the end of a session, so the
  oldest are the ones that can be dropped
  @note Nothing is recorded unless M5_UNIT_NFC_EMULATION_TRACE is defined. Without it the calls
  compile away and neither memory nor time is spent
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_EMULATION_TRACE_HPP
#define M5_UNIT_NFC_NFC_LAYER_EMULATION_TRACE_HPP

#include <stdint.h>

#if defined(M5_UNIT_NFC_EMULATION_TRACE)
#include <stdio.h>
#include <M5Utility.hpp>
#endif

// Folding repeats keeps one session down to a handful of entries, so this covers more than a dozen
// approaches of a reader
#if !defined(M5_UNIT_NFC_EMULATION_TRACE_MAX)
#define M5_UNIT_NFC_EMULATION_TRACE_MAX (128)
#endif

namespace m5 {
namespace nfc {
namespace emulation {

/*
  Records what the adapter state machine saw, to be printed later
  @details The names of the events are given by the adapter, so NFC-A and NFC-F can use their own
  state names while sharing this recorder
 */
class Trace {
public:
    /*
      @param names Event names, indexed by the value given to record()
      @param num Number of names
     */
    Trace(const char* const* names, const uint8_t num) : _names{names}, _num{num}
    {
    }

    /*
      Append one entry, or count it against the previous one when it repeats
      @param ev Event, an index into the names given to the constructor
      @param irq Interrupt bits that were seen, if any
      @param detail Anything the adapter wants to keep, such as a register value
     */
    void record(const uint8_t ev, const uint32_t irq = 0, const uint8_t detail = 0)
    {
#if defined(M5_UNIT_NFC_EMULATION_TRACE)
        const uint32_t now = m5::utility::millis();

        // A reader polling a halted PICC produces two events in turn, so matching only the entry
        // just before would never fold them. The interrupt bits are left out of the comparison
        // because the same situation reports slightly different bits from one poll to the next;
        // what was seen is kept by collecting the bits into the entry
        const uint16_t look = (_count < LOOKBACK) ? _count : LOOKBACK;
        for (uint_fast16_t back = 1; back <= look; ++back) {
            auto& e = _entry[(_head + _count - back) % MAX];
            if (e.ev == ev && e.detail == detail) {
                if (e.count < 0xFFFF) {
                    ++e.count;
                }
                e.irq |= irq;
                const uint32_t span = now - e.ms;
                e.span              = (span > 0xFFFF) ? 0xFFFF : (uint16_t)span;
                return;
            }
        }

        if (_count < MAX) {
            _entry[(_head + _count++) % MAX] = Entry{now, irq, 1, 0, ev, detail};
        } else {
            // The buffer holds the newest, so the oldest one makes room
            _entry[_head] = Entry{now, irq, 1, 0, ev, detail};
            _head         = (_head + 1) % MAX;
            ++_dropped;
        }
#else
        (void)ev;
        (void)irq;
        (void)detail;
#endif
    }

    /*
      Print what was recorded and start over
      @warning Printing takes milliseconds, so call it while the emulation is not answering
     */
    void dump()
    {
#if defined(M5_UNIT_NFC_EMULATION_TRACE)
        if (!_count) {
            return;
        }
        printf("---- emulation trace %u", _count);
        if (_dropped) {
            printf(" (%u older dropped)", _dropped);
        }
        printf(" ----\n");

        for (uint_fast16_t i = 0; i < _count; ++i) {
            const auto& e = _entry[(_head + i) % MAX];
            printf("T[%03u] %7u %-9s irq:%08X detail:%02X", (unsigned)i, (unsigned)e.ms,
                   (e.ev < _num) ? _names[e.ev] : "?", (unsigned)e.irq, e.detail);
            if (e.count > 1) {
                printf(" x%u (%u ms)", e.count, e.span);
            }
            printf("\n");
        }
        clear();
#endif
    }

    //! Forget what was recorded without printing it
    void clear()
    {
#if defined(M5_UNIT_NFC_EMULATION_TRACE)
        _count   = 0;
        _head    = 0;
        _dropped = 0;
#endif
    }

private:
#if defined(M5_UNIT_NFC_EMULATION_TRACE)
    struct Entry {
        uint32_t ms;     // When the first of the repeats was seen
        uint32_t irq;    //
        uint16_t count;  // How many times in a row
        uint16_t span;   // Milliseconds between the first and the last repeat
        uint8_t ev;      //
        uint8_t detail;  //
    };
    static constexpr uint16_t MAX{M5_UNIT_NFC_EMULATION_TRACE_MAX};
    // How far back a repeat is looked for. Two is enough for the pairs a polling reader produces
    static constexpr uint16_t LOOKBACK{2};
    Entry _entry[MAX]{};
    uint16_t _head{}, _count{}, _dropped{};
#endif
    const char* const* _names{};
    uint8_t _num{};
};

}  // namespace emulation
}  // namespace nfc
}  // namespace m5
#endif
