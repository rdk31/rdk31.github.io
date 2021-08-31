+++
title = "YauzaCTF 2021 - RISC 8bit CPU"
date = 2021-08-31
[taxonomies]
categories = ["ctfs"]
tags = ["yauzactf2021", "python"]
+++

# Task description

The SFT0 CPU is a secure processor designed to store encryption key. Find out how the processor works and get the key.

[manual.pdf](/files/yauzactf2021/risc8bitcpu/manual.pdf)

[rom.bin](/files/yauzactf2021/risc8bitcpu/rom.bin)

# Solution

This is a simple CPU architecture containing 3 8bit registers, a pc register and 1bit flag register (zero flag). The instructions are 4 bytes in big endian.

And this is the emulator.

```python
#!/usr/bin/env python

import re

pc = 0x1000
regs = [0] * 3
fr = 0
halt = False

rom = open("rom.bin", "rb").read()
ram = bytearray(rom) + bytearray([0] * (0xFFFF - len(rom)))


def add(reg, val):
    global regs
    regs[reg] += val
    regs[reg] &= 0xFF


def xor(reg, val):
    global regs
    regs[reg] ^= val


def and_op(reg, val):
    global regs
    regs[reg] &= val


def or_op(reg, val):
    global regs
    regs[reg] |= val


def ld(reg, val):
    global regs
    regs[reg] = val


def mov(reg1, reg2):
    global regs
    regs[reg1] = regs[reg2]


def ldr(reg, addr):
    global regs, ram
    regs[reg] = int.from_bytes(ram[addr], byteorder="big")


def ldr2(reg):
    global regs, ram
    addr = regs[1] << 8 | regs[2]
    regs[reg] = ram[addr]


def str_op(reg, addr):
    global regs, ram
    ram[addr] = int.to_bytes(regs[reg], byteorder="big")


def str2_op(reg):
    global regs, ram
    addr = regs[1] << 8 | regs[2]
    ram[addr] = regs[reg]


def put(reg):
    global regs, out
    print(chr(regs[reg]), end="")


def jmp(addr):
    global pc
    pc = addr


def jnz(addr):
    global pc, fr
    if fr == 0:
        pc = addr


def jz(addr):
    global pc, fr
    if fr == 1:
        pc = addr


def cmpeq(reg, val):
    global regs, fr
    if regs[reg] == val:
        fr = 1
    else:
        fr = 0


def hlt():
    global halt
    halt = True


def nop():
    pass


ops = {
    "add": [b"\x00(.)\x00(.)", add],
    "xor": [b"\x01(.)\x00(.)", xor],
    "and": [b"\x02(.)\x00(.)", and_op],
    "or": [b"\x03(.)\x00(.)", or_op],
    "ld": [b"\x04(.)\x00(.)", ld],
    "mov": [b"\x05(.)\x00(.)", mov],
    "ldr": [b"\x06(.)(..)", ldr],
    "ldr2": [b"\x07(.)\x00\x00", ldr2],
    "str": [b"\x08(.)(..)", str_op],
    "str2": [b"\x09(.)\x00\x00", str2_op],
    "put": [b"\x0A(.)\x00\x00", put],
    "jmp": [b"\x0B\x00(..)", jmp],
    "jnz": [b"\x0C\x00(..)", jnz],
    "jz": [b"\x0D\x00(..)", jz],
    "cmpeq": [b"\x0E(.)\x00(.)", cmpeq],
    "hlt": [b"\x44\x44\x44\x44", hlt],
    "nop": [b"\x33\x33\x33\x33", nop],
}


def parse(op):
    for k, v in ops.items():
        r = re.search(v[0], op)
        if r:
            v[1](*[int.from_bytes(x, byteorder="big") for x in r.groups()])
            break


while not halt:
    parse(ram[pc : pc + 4])

    pc += 4
```

Running the emulator prints out the flag:

```

                                                        @@@@@@@*
                                                    @@@@@       &@@@@
        @@@@@@@@@@(@@@@@@@@@@ @@@@@@@@@@(@@@@@@@@@@ @@               @@@
        @@@@@@@&  (@@@           @@@%   (@@  @@/@@@ @@   @       @(  @@@
        #@@@@@@@@(@@@ @@@@@@    @@@%   (@@ @@  @@@ @@   @        ,@ @@@
        @@@@@@@@@@(@@@           @@@%   (@@@@@@@@@@ @@               @@@
                                                    @@@@@       /@@@@
                                                    @@  @@@@@@@&
                                                    @@@@
                                                @@@@@
                                                @@@@
                                                &@

    Top secret.
    Authorized personnel only.
    YauzaCTF{s0_s3cr3t_y3t_s0_fr33}
```

Interestingly enough, this emulator has a bug that I haven't noticed until the task author notified everybody that he had made a mistake creating the rom file. In my code, I increment pc after each op. That means also after a successful jump, skipping the first instruction after it. Luckily, the author had made the same mistake creating the file, so it canceled out.
