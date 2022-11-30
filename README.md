# bextr helper
* Plugin search for mov --> bextr pairs and create easy to read operation as a comment. You can actually get similar output in decompiler, but sometime is just easier to read disassembly.

## Usage
* Push F10 on line that bextr instruction is.
* To resolve all bextr instructions in database, comment single_bextr(), and uncomment multi_bextr(), Then reopen ida to reload plugin. Now push F10, and wait patiently.

## Bugs
* Plugin search for compatible mov instruction up to 30 opcodes before bextr, sometime this is not enough.

## Requirements
* Dunno. Run fine in IDA 7.5 with python 3.

## Preview
