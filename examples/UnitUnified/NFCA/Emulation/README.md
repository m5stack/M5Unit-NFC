# NFC-A Emulation

Emulates an NTAG 21x or MIFARE Ultralight tag. Choose the type with the `EMU_*` define near the top
of the sketch.

Overriding `receive_callback()` lets the sketch answer commands the library does not handle. The
example does this for `READ_CNT`, which only NTAG 213/215/216 carry.

## MIFARE Classic cannot be emulated

**The ST25R3916 cannot emulate a MIFARE Classic card**, so no `EMU_*` option offers one.

MIFARE Classic computes each parity bit from the plaintext and then encrypts it, so the card has to
place the parity bits itself. The chip's `no_tx_par` / `no_rx_par` bits are the only way to do that,
and the datasheet marks both as *"Supported in reader modes only, not supported in card emulation
modes"* (DS12484, Table 27). ST confirms this directly:

> Emulating a Mifare 1K card would require host-defined parity bits. **This is not possible on
> ST25R39xx.**
>
> <https://community.st.com/t5/st25-nfc-rfid-tags-and-readers/how-rfal-for-st25r39xx-emulate-mifare-one-1k-card/td-p/86276>

Reading and writing MIFARE Classic cards **as a reader** is fully supported — see the
[ReadWrite](../ReadWrite) and [Dump](../Dump) examples.
