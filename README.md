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
Before:
![bef](https://user-images.githubusercontent.com/101417270/204716235-e93733cd-5211-40ed-b68f-b43e82ec52c2.jpg)

After:
![aft](https://user-images.githubusercontent.com/101417270/204716270-6288e454-d6b1-4383-9c89-0ea503b7e9c8.jpg)
