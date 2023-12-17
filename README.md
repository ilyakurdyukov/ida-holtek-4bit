## Holtek HT1130 support for IDA 7.x

Place the `ht1130.py` in the `procs` directory.
If you don't see "Holtek HT1130 (ht1130)" in the CPU selection, then check if Python support is working in IDA.

* This instruction set is heavily inspired by Intel's 4/8-bit instruction sets.

* The biggest problem is finding a ROM for this module. Because you can only get a ROM by photographing a chip's crystal under a microscope. The only known dump is [here](https://github.com/azya52/BrickEmuPy/blob/main/assets/E23PlusMarkII96in1.bin).

### Other 4-bit microcontrollers from Holtek

HT44300/HT443A0: same opcodes as HT1130.

HTG12G0, HTG1390, HTG13J0: doesn't have opcode 0x32 (was `IN A, PM`).

HTG12N0: opcode 0x34 is read as `OUT PC, A` (was `IN A, PP`).

HTG12B0 is different for ~10 opcodes.

