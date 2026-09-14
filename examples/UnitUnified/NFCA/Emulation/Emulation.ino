/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  NFC-A Emulation mode
*/
// *************************************************************
// Choose ONE define symbol to match the unit you are using
// NOTE: Emulation is supported ONLY on UnitNFC (ST25R3916) and CapCC1101NFC (ST25R3916).
//       UnitRFID2 (WS1850S) and M5Dial Builtin (WS1850S) do NOT support emulation.
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
#endif
#include "main/Emulation.cpp"
